#!/usr/bin/env python3
"""Stream WAF request cases and run each through an isolated k6 process."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()


def atomic_write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def archive_manifest(source: Path, destination: Path) -> None:
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with source.open("rb") as input_handle, temporary.open("wb") as raw_output:
        with gzip.GzipFile(fileobj=raw_output, mode="wb", compresslevel=6, mtime=0) as output_handle:
            shutil.copyfileobj(input_handle, output_handle)
    temporary.replace(destination)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def metric_value(summary: dict[str, Any], metric: str, field: str) -> float | None:
    value = summary.get("metrics", {}).get(metric, {}).get("values", {}).get(field)
    return float(value) if isinstance(value, (int, float)) else None


def compact_summary(summary_path: Path) -> dict[str, float | None]:
    if not summary_path.exists():
        return {}
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        "http_reqs": metric_value(summary, "http_reqs", "count"),
        "http_req_failed_rate": metric_value(summary, "http_req_failed", "rate"),
        "http_req_duration_p95_ms": metric_value(summary, "http_req_duration", "p(95)"),
        "http_req_duration_max_ms": metric_value(summary, "http_req_duration", "max"),
        "dropped_iterations": metric_value(summary, "dropped_iterations", "count"),
        "checks_rate": metric_value(summary, "checks", "rate"),
        "data_sent_bytes": metric_value(summary, "data_sent", "count"),
        "data_received_bytes": metric_value(summary, "data_received", "count"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sequentially run streamed WAF payload cases with k6")
    parser.add_argument("--target", required=True, help="Base target URL, e.g. https://waf.example")
    parser.add_argument("--payload-file", default="payloads.jsonl", help="JSONL manifest; legacy JSON arrays are also supported")
    parser.add_argument("--k6-script", default="k6_run_payloads.js")
    parser.add_argument("--rps", type=int, default=10)
    parser.add_argument("--duration", default="30s")
    parser.add_argument("--cooldown", type=float, default=5.0)
    parser.add_argument("--start-index", type=int, default=0, help="Zero-based source manifest index")
    parser.add_argument("--limit", type=int, help="Maximum number of matching cases to execute")
    parser.add_argument("--case-id", help="Execute only the exact case ID")
    parser.add_argument("--format", dest="formats", action="append", help="Filter metadata.format; repeatable")
    parser.add_argument("--structure", dest="structures", action="append", help="Filter metadata.structure; repeatable")
    parser.add_argument("--value-encoding", dest="value_encodings", action="append", help="Filter metadata.value_encoding; repeatable")
    parser.add_argument("--charset", dest="charsets", action="append", help="Filter metadata.charset; repeatable")
    parser.add_argument("--compression", dest="compressions", action="append", help="Filter metadata.compression; repeatable")
    parser.add_argument("--validity", dest="validities", action="append", choices=["valid", "invalid", "invalid-compression"], help="Filter metadata.validity; repeatable")
    parser.add_argument("--list", action="store_true", help="Print matching case summaries without running k6")
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--preallocated-vus", type=int)
    parser.add_argument("--max-vus", type=int)
    parser.add_argument("--terminate-timeout", type=float, default=10.0)
    return parser.parse_args()


def detect_manifest_format(path: Path) -> str:
    with path.open("r", encoding="utf-8") as handle:
        while True:
            char = handle.read(1)
            if not char:
                raise ValueError("payload manifest is empty")
            if not char.isspace():
                return "json" if char == "[" else "jsonl"


def iter_manifest(path: Path, manifest_format: str) -> Iterator[tuple[int, dict[str, Any]]]:
    if manifest_format == "jsonl":
        with path.open("r", encoding="utf-8") as handle:
            source_index = 0
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    case = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
                if not isinstance(case, dict):
                    raise ValueError(f"JSONL line {line_number} is not an object")
                yield source_index, case
                source_index += 1
        return

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("legacy JSON manifest must be an array")
    for source_index, case in enumerate(data):
        if not isinstance(case, dict):
            raise ValueError(f"JSON array item {source_index} is not an object")
        yield source_index, case


def matches_filter(value: Any, allowed: list[str] | None) -> bool:
    return allowed is None or str(value) in allowed


def case_matches(case: dict[str, Any], args: argparse.Namespace) -> bool:
    if args.case_id and case.get("id") != args.case_id:
        return False
    metadata = case.get("metadata") or {}
    return all((
        matches_filter(metadata.get("format"), args.formats),
        matches_filter(metadata.get("structure"), args.structures),
        matches_filter(metadata.get("value_encoding"), args.value_encodings),
        matches_filter(metadata.get("charset"), args.charsets),
        matches_filter(metadata.get("compression"), args.compressions),
        matches_filter(metadata.get("validity"), args.validities),
    ))


def selected_cases(path: Path, manifest_format: str, args: argparse.Namespace) -> Iterator[tuple[int, dict[str, Any]]]:
    matched = 0
    for source_index, case in iter_manifest(path, manifest_format):
        if source_index < args.start_index:
            continue
        if not case_matches(case, args):
            continue
        yield source_index, case
        matched += 1
        if args.limit is not None and matched >= args.limit:
            return


def terminate_process(process: subprocess.Popen[Any], timeout: float) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=max(0.1, timeout))
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def preserve_interrupted_artifacts(results_dir: Path, case: dict[str, Any], index: int, started_at: str, paths: tuple[Path, Path, Path]) -> None:
    interrupted = results_dir / "interrupted"
    interrupted.mkdir(parents=True, exist_ok=True)
    atomic_write_json(interrupted / "request.json", {"index": index, "started_at": started_at, "request": case})
    for source, name in zip(paths, ("k6-summary.json", "stdout.log", "stderr.log")):
        if source.exists():
            shutil.copy2(source, interrupted / name)


def main() -> int:
    args = parse_args()
    if args.start_index < 0 or (args.limit is not None and args.limit < 1):
        print("ERROR: --start-index must be >= 0 and --limit must be >= 1", file=sys.stderr)
        return 2

    payload_path = Path(args.payload_file).resolve()
    script_path = Path(args.k6_script).resolve()
    if not payload_path.is_file() or not script_path.is_file():
        print("ERROR: payload file or k6 script does not exist", file=sys.stderr)
        return 2

    try:
        manifest_format = detect_manifest_format(payload_path)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.list:
        count = 0
        try:
            for index, case in selected_cases(payload_path, manifest_format, args):
                print(json.dumps({"index": index, "case_id": case.get("id"), "wire_body_size": case.get("wire_body_size"), "metadata": case.get("metadata")}, ensure_ascii=False))
                count += 1
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"Matched cases: {count}", file=sys.stderr)
        return 0 if count else 3

    if shutil.which("k6") is None:
        print("ERROR: k6 executable was not found in PATH", file=sys.stderr)
        return 2

    run_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    results_dir = Path(args.results_dir) / run_id
    results_dir.mkdir(parents=True, exist_ok=False)
    journal = results_dir / "run.jsonl"
    active_path = results_dir / "active_case.json"
    archive_name = "payloads.jsonl.gz" if manifest_format == "jsonl" else "payloads.json.gz"
    archived_payload_path = results_dir / archive_name
    archive_manifest(payload_path, archived_payload_path)

    run_config = {
        "run_id": run_id,
        "target": args.target,
        "rps": args.rps,
        "duration": args.duration,
        "cooldown": args.cooldown,
        "start_index": args.start_index,
        "limit": args.limit,
        "case_id": args.case_id,
        "filters": {
            "format": args.formats,
            "structure": args.structures,
            "value_encoding": args.value_encodings,
            "charset": args.charsets,
            "compression": args.compressions,
            "validity": args.validities,
        },
        "payload_file": str(payload_path),
        "payload_manifest_format": manifest_format,
        "archived_payload_file": str(archived_payload_path),
        "payload_manifest_sha256": file_sha256(payload_path),
        "k6_script": str(script_path),
        "storage_mode": "compact-streaming",
        "automatic_retry": False,
        "automatic_stop": False,
    }
    atomic_write_json(results_dir / "run_config.json", run_config)
    append_jsonl(journal, {"event": "RUN_START", "timestamp": utc_now(), **run_config})

    completed_cases = 0
    nonzero_exit_codes = 0
    current_process: subprocess.Popen[Any] | None = None
    current_case: dict[str, Any] | None = None
    current_index: int | None = None
    current_started_at: str | None = None
    current_temp_paths: tuple[Path, Path, Path] | None = None

    try:
        with tempfile.TemporaryDirectory(prefix=f"waf-payload-{run_id}-") as temp_name:
            temp_dir = Path(temp_name)
            case_file = temp_dir / "current_case.json"
            for index, case in selected_cases(payload_path, manifest_format, args):
                case_id = case.get("id", f"index-{index}")
                started_at = utc_now()
                current_case, current_index, current_started_at = case, index, started_at
                start_record = {
                    "event": "CASE_START", "timestamp": started_at, "run_id": run_id,
                    "index": index, "case_id": case_id, "sha256": case.get("sha256"),
                    "wire_body_size": case.get("wire_body_size"), "metadata": case.get("metadata"),
                }
                atomic_write_json(active_path, {"run_id": run_id, "active": start_record, "completed": False})
                append_jsonl(journal, start_record)
                print(json.dumps(start_record, ensure_ascii=False), flush=True)

                atomic_write_json(case_file, case)
                summary_path = temp_dir / "current.summary.json"
                stdout_path = temp_dir / "current.stdout.log"
                stderr_path = temp_dir / "current.stderr.log"
                current_temp_paths = (summary_path, stdout_path, stderr_path)
                for path in current_temp_paths:
                    path.unlink(missing_ok=True)

                env = os.environ.copy()
                env.update({
                    "TARGET_URL": args.target, "CASE_FILE": str(case_file), "CASE_INDEX": str(index),
                    "RUN_ID": run_id, "RPS": str(args.rps), "DURATION": args.duration,
                })
                if args.preallocated_vus is not None:
                    env["PREALLOCATED_VUS"] = str(args.preallocated_vus)
                if args.max_vus is not None:
                    env["MAX_VUS"] = str(args.max_vus)

                command = ["k6", "run", "--summary-export", str(summary_path), str(script_path)]
                started = time.monotonic()
                with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
                    current_process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr)
                    exit_code = current_process.wait()
                current_process = None

                end_record = {
                    "event": "CASE_END", "timestamp": utc_now(), "run_id": run_id,
                    "index": index, "case_id": case_id, "exit_code": exit_code,
                    "elapsed_seconds": round(time.monotonic() - started, 3), "metrics": compact_summary(summary_path),
                }
                append_jsonl(journal, end_record)
                print(json.dumps(end_record, ensure_ascii=False), flush=True)
                completed_cases += 1
                nonzero_exit_codes += int(exit_code != 0)
                atomic_write_json(active_path, {"run_id": run_id, "active": None, "last_completed": end_record, "completed": False})
                for path in current_temp_paths:
                    path.unlink(missing_ok=True)
                case_file.unlink(missing_ok=True)
                current_case = current_index = current_started_at = current_temp_paths = None
                if args.cooldown > 0:
                    time.sleep(args.cooldown)

    except (ValueError, OSError) as exc:
        append_jsonl(journal, {"event": "RUN_ERROR", "timestamp": utc_now(), "run_id": run_id, "error": str(exc)})
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        if current_process is not None:
            terminate_process(current_process, args.terminate_timeout)
        interrupted_at = utc_now()
        interruption = {
            "event": "RUN_INTERRUPTED", "timestamp": interrupted_at, "run_id": run_id, "reason": "SIGINT",
            "active_index": current_index,
            "active_case_id": current_case.get("id", f"index-{current_index}") if current_case is not None else None,
            "active_case_sha256": current_case.get("sha256") if current_case is not None else None,
        }
        if current_case is not None and current_index is not None and current_started_at is not None:
            if current_temp_paths is not None:
                preserve_interrupted_artifacts(results_dir, current_case, current_index, current_started_at, current_temp_paths)
            atomic_write_json(active_path, {
                "run_id": run_id,
                "active": {"index": current_index, "case_id": interruption["active_case_id"], "sha256": interruption["active_case_sha256"], "started_at": current_started_at},
                "interrupted_at": interrupted_at, "completed": False,
            })
        append_jsonl(journal, interruption)
        print(json.dumps(interruption, ensure_ascii=False), flush=True)
        print(f"Interrupted results: {results_dir}")
        return 130

    if completed_cases == 0:
        append_jsonl(journal, {"event": "RUN_END", "timestamp": utc_now(), "run_id": run_id, "completed_cases": 0, "nonzero_exit_codes": 0, "no_matches": True})
        atomic_write_json(active_path, {"run_id": run_id, "active": None, "completed": True, "completed_at": utc_now(), "no_matches": True})
        print("No cases matched the selection", file=sys.stderr)
        return 3

    atomic_write_json(active_path, {"run_id": run_id, "active": None, "completed": True, "completed_at": utc_now()})
    append_jsonl(journal, {"event": "RUN_END", "timestamp": utc_now(), "run_id": run_id, "completed_cases": completed_cases, "nonzero_exit_codes": nonzero_exit_codes})
    print(f"Results: {results_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
