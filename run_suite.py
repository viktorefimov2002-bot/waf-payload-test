#!/usr/bin/env python3
"""Run every generated request case in an isolated k6 process."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        handle.flush()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sequentially run WAF payload cases with k6")
    parser.add_argument("--target", required=True, help="Base target URL, e.g. https://waf.example")
    parser.add_argument("--payload-file", default="payloads.json")
    parser.add_argument("--k6-script", default="k6_run_payloads.js")
    parser.add_argument("--rps", type=int, default=10)
    parser.add_argument("--duration", default="30s")
    parser.add_argument("--cooldown", type=float, default=5.0)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--stop-on-failure", action="store_true")
    parser.add_argument("--preallocated-vus", type=int)
    parser.add_argument("--max-vus", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if shutil.which("k6") is None:
        print("ERROR: k6 executable was not found in PATH", file=sys.stderr)
        return 2

    payload_path = Path(args.payload_file).resolve()
    script_path = Path(args.k6_script).resolve()
    cases = json.loads(payload_path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        print("ERROR: payload manifest is empty or invalid", file=sys.stderr)
        return 2

    end = len(cases) if args.limit is None else min(len(cases), args.start_index + args.limit)
    selected = range(args.start_index, end)
    run_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    results_dir = Path(args.results_dir) / run_id
    results_dir.mkdir(parents=True, exist_ok=False)
    journal = results_dir / "run.jsonl"

    append_jsonl(journal, {
        "event": "RUN_START",
        "timestamp": utc_now(),
        "run_id": run_id,
        "target": args.target,
        "rps": args.rps,
        "duration": args.duration,
        "start_index": args.start_index,
        "end_index_exclusive": end,
    })

    failures = 0
    for index in selected:
        case = cases[index]
        case_id = case.get("id", f"index-{index}")
        summary_path = results_dir / f"{index:06d}-{case_id}.summary.json"
        stdout_path = results_dir / f"{index:06d}-{case_id}.stdout.log"
        stderr_path = results_dir / f"{index:06d}-{case_id}.stderr.log"

        start_record = {
            "event": "CASE_START",
            "timestamp": utc_now(),
            "run_id": run_id,
            "index": index,
            "case_id": case_id,
            "sha256": case.get("sha256"),
            "wire_body_size": case.get("wire_body_size"),
            "metadata": case.get("metadata"),
        }
        append_jsonl(journal, start_record)
        print(json.dumps(start_record, ensure_ascii=False), flush=True)

        env = os.environ.copy()
        env.update({
            "TARGET_URL": args.target,
            "PAYLOAD_FILE": str(payload_path),
            "PAYLOAD_INDEX": str(index),
            "RUN_ID": run_id,
            "RPS": str(args.rps),
            "DURATION": args.duration,
        })
        if args.preallocated_vus is not None:
            env["PREALLOCATED_VUS"] = str(args.preallocated_vus)
        if args.max_vus is not None:
            env["MAX_VUS"] = str(args.max_vus)

        command = ["k6", "run", "--summary-export", str(summary_path), str(script_path)]
        started = time.monotonic()
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
            result = subprocess.run(command, env=env, stdout=stdout, stderr=stderr, check=False)
        elapsed = time.monotonic() - started

        end_record = {
            "event": "CASE_END",
            "timestamp": utc_now(),
            "run_id": run_id,
            "index": index,
            "case_id": case_id,
            "exit_code": result.returncode,
            "elapsed_seconds": round(elapsed, 3),
            "summary_file": str(summary_path),
            "stdout_file": str(stdout_path),
            "stderr_file": str(stderr_path),
        }
        append_jsonl(journal, end_record)
        print(json.dumps(end_record, ensure_ascii=False), flush=True)

        if result.returncode != 0:
            failures += 1
            if args.stop_on_failure:
                break
        if args.cooldown > 0:
            time.sleep(args.cooldown)

    append_jsonl(journal, {
        "event": "RUN_END",
        "timestamp": utc_now(),
        "run_id": run_id,
        "failures": failures,
    })
    print(f"Results: {results_dir}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
