#!/usr/bin/env python3
"""Run generated WAF request cases sequentially and preserve reproducible evidence."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        handle.flush()


def atomic_write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


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
    parser.add_argument("--retry-suspicious", type=int, default=1, help="Additional attempts for suspicious cases")
    parser.add_argument("--retry-cooldown", type=float, default=10.0)
    parser.add_argument("--recent-history", type=int, default=10, help="Number of latest cases written to active_cases.json")
    parser.add_argument("--health-url", help="Optional URL checked before and after each case")
    parser.add_argument("--health-timeout", type=float, default=5.0)
    parser.add_argument("--health-expected", type=int, nargs="+", default=[200, 204, 301, 302, 401, 403])
    parser.add_argument("--health-retries", type=int, default=3)
    parser.add_argument("--suspicious-status-rate", type=float, default=0.01, help="Failure-rate threshold parsed from k6 summary")
    return parser.parse_args()


def health_check(url: str | None, timeout: float, expected: set[int], retries: int) -> dict[str, Any]:
    if not url:
        return {"configured": False, "ok": True}
    last: dict[str, Any] = {"configured": True, "ok": False}
    for attempt in range(1, retries + 1):
        try:
            request = Request(url, method="GET", headers={"User-Agent": "waf-payload-test-health/1.0"})
            with urlopen(request, timeout=timeout) as response:
                status = response.status
            last = {"configured": True, "ok": status in expected, "status": status, "attempt": attempt}
        except HTTPError as exc:
            last = {"configured": True, "ok": exc.code in expected, "status": exc.code, "attempt": attempt}
        except (URLError, TimeoutError, OSError) as exc:
            last = {"configured": True, "ok": False, "error": str(exc), "attempt": attempt}
        if last["ok"]:
            return last
        if attempt < retries:
            time.sleep(1.0)
    return last


def metric_value(summary: dict[str, Any], metric: str, field: str) -> float | None:
    value = summary.get("metrics", {}).get(metric, {}).get("values", {}).get(field)
    return float(value) if isinstance(value, (int, float)) else None


def classify_attempt(exit_code: int, summary_path: Path, health_after: dict[str, Any], threshold: float) -> dict[str, Any]:
    reasons: list[str] = []
    metrics: dict[str, float | None] = {}
    if exit_code != 0:
        reasons.append(f"k6-exit-{exit_code}")
    if not health_after.get("ok", True):
        reasons.append("health-check-failed")
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            metrics = {
                "http_req_failed_rate": metric_value(summary, "http_req_failed", "rate"),
                "dropped_iterations": metric_value(summary, "dropped_iterations", "count"),
                "checks_rate": metric_value(summary, "checks", "rate"),
                "http_req_duration_p95": metric_value(summary, "http_req_duration", "p(95)"),
            }
            failure_rate = metrics["http_req_failed_rate"]
            if failure_rate is not None and failure_rate >= threshold:
                reasons.append("http-failure-rate")
            dropped = metrics["dropped_iterations"]
            if dropped is not None and dropped > 0:
                reasons.append("dropped-iterations")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            reasons.append(f"summary-unreadable:{exc}")
    else:
        reasons.append("summary-missing")
    return {"suspicious": bool(reasons), "reasons": reasons, "metrics": metrics}


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
    active_path = results_dir / "active_cases.json"
    suspicious_path = results_dir / "suspicious_cases.jsonl"
    recent: deque[dict[str, Any]] = deque(maxlen=max(1, args.recent_history))

    run_config = {
        "run_id": run_id,
        "target": args.target,
        "health_url": args.health_url,
        "rps": args.rps,
        "duration": args.duration,
        "cooldown": args.cooldown,
        "start_index": args.start_index,
        "end_index_exclusive": end,
        "payload_file": str(payload_path),
        "payload_manifest_sha256": __import__("hashlib").sha256(payload_path.read_bytes()).hexdigest(),
        "k6_script": str(script_path),
        "retry_suspicious": args.retry_suspicious,
    }
    atomic_write_json(results_dir / "run_config.json", run_config)
    append_jsonl(journal, {"event": "RUN_START", "timestamp": utc_now(), **run_config})

    failures = 0
    suspicious_count = 0
    health_expected = set(args.health_expected)

    for index in selected:
        case = cases[index]
        case_id = case.get("id", f"index-{index}")
        recent.append({"index": index, "case_id": case_id, "sha256": case.get("sha256"), "timestamp": utc_now()})
        atomic_write_json(active_path, {"run_id": run_id, "currently_active": recent[-1], "recent": list(recent)})

        health_before = health_check(args.health_url, args.health_timeout, health_expected, args.health_retries)
        append_jsonl(journal, {"event": "HEALTH_BEFORE", "timestamp": utc_now(), "index": index, "case_id": case_id, **health_before})
        if not health_before.get("ok", True):
            failures += 1
            append_jsonl(suspicious_path, {"timestamp": utc_now(), "index": index, "case_id": case_id, "reason": "health-failed-before-case"})
            if args.stop_on_failure:
                break

        maximum_attempts = 1 + max(0, args.retry_suspicious)
        case_suspicious = False
        for attempt in range(1, maximum_attempts + 1):
            stem = f"{index:06d}-{case_id}-attempt{attempt}"
            summary_path = results_dir / f"{stem}.summary.json"
            stdout_path = results_dir / f"{stem}.stdout.log"
            stderr_path = results_dir / f"{stem}.stderr.log"
            start_record = {
                "event": "CASE_START",
                "timestamp": utc_now(),
                "run_id": run_id,
                "index": index,
                "attempt": attempt,
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
            health_after = health_check(args.health_url, args.health_timeout, health_expected, args.health_retries)
            classification = classify_attempt(result.returncode, summary_path, health_after, args.suspicious_status_rate)

            end_record = {
                "event": "CASE_END",
                "timestamp": utc_now(),
                "run_id": run_id,
                "index": index,
                "attempt": attempt,
                "case_id": case_id,
                "exit_code": result.returncode,
                "elapsed_seconds": round(elapsed, 3),
                "health_after": health_after,
                **classification,
                "summary_file": str(summary_path),
                "stdout_file": str(stdout_path),
                "stderr_file": str(stderr_path),
            }
            append_jsonl(journal, end_record)
            print(json.dumps(end_record, ensure_ascii=False), flush=True)

            if classification["suspicious"]:
                case_suspicious = True
                append_jsonl(suspicious_path, {**start_record, **end_record, "case": case})
                atomic_write_json(results_dir / "last_suspicious_case.json", {"case": case, "result": end_record, "recent": list(recent)})
                if attempt < maximum_attempts:
                    time.sleep(max(0, args.retry_cooldown))
                    continue
            break

        if case_suspicious:
            suspicious_count += 1
            failures += 1
            if args.stop_on_failure:
                break
        if args.cooldown > 0:
            time.sleep(args.cooldown)

    atomic_write_json(active_path, {"run_id": run_id, "currently_active": None, "recent": list(recent), "completed": True})
    append_jsonl(journal, {
        "event": "RUN_END",
        "timestamp": utc_now(),
        "run_id": run_id,
        "failures": failures,
        "suspicious_cases": suspicious_count,
    })
    print(f"Results: {results_dir}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
