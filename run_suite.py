#!/usr/bin/env python3
"""Run streamed WAF payload cases through k6 in fast, informative, or high-RPS mode."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
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


def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def archive_manifest(source: Path, destination: Path) -> None:
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with source.open("rb") as source_handle, temporary.open("wb") as raw_output:
        with gzip.GzipFile(fileobj=raw_output, mode="wb", compresslevel=6, mtime=0) as output:
            shutil.copyfileobj(source_handle, output)
    temporary.replace(destination)


def parse_args() -> argparse.Namespace:
    examples = """examples:
  Fast sweep:
    python3 run_suite.py --mode fast --target https://waf.example \\
      --payload-file payloads.jsonl --rps 1 --duration 1s --cooldown 0

  Recheck a suspicious range:
    python3 run_suite.py --mode informative --target https://waf.example \\
      --payload-file payloads.jsonl --start-index 275 --limit 25

  High-RPS verification:
    python3 run_suite.py --mode high-rps --target https://waf.example \\
      --payload-file payloads.jsonl --rps 500 --duration 5s \\
      --preallocated-vus 100 --max-vus 500
"""
    parser = argparse.ArgumentParser(
        description=(
            "Run byte-exact WAF payload cases through k6. "
            "The runner supports a fast batched sweep, isolated informative runs, "
            "and sequential high-RPS scenarios."
        ),
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    source = parser.add_argument_group("target and input")
    source.add_argument(
        "--target", required=True, metavar="URL",
        help="Base target URL, for example https://waf.example. Case paths are appended to it.",
    )
    source.add_argument(
        "--payload-file", default="payloads.jsonl", metavar="FILE",
        help="JSONL manifest or legacy JSON array (default: payloads.jsonl).",
    )
    source.add_argument(
        "--k6-script", default="k6_run_payloads.js", metavar="FILE",
        help="k6 JavaScript scenario file (default: k6_run_payloads.js).",
    )

    execution = parser.add_argument_group("execution")
    execution.add_argument(
        "--mode", choices=["fast", "informative", "high-rps"], default="fast",
        help=(
            "Execution mode: fast batches sequential cases in one k6 process; "
            "informative isolates one case per process; high-rps assigns each case "
            "a sequential constant-arrival-rate scenario (default: fast)."
        ),
    )
    execution.add_argument(
        "--batch-size", type=int, metavar="N",
        help="Cases per k6 process. Defaults: fast=25, informative=1, high-rps=10.",
    )
    execution.add_argument(
        "--rps", type=int, default=10, metavar="N",
        help="Target requests per second for the active case (default: 10).",
    )
    execution.add_argument(
        "--duration", default="30s", metavar="TIME",
        help="Traffic duration for each case, such as 1s, 30s or 2m (default: 30s).",
    )
    execution.add_argument(
        "--cooldown", type=float, default=5.0, metavar="SECONDS",
        help="Pause between cases inside a batch (default: 5.0). Use 0 for no pause.",
    )
    execution.add_argument(
        "--graceful-stop", default="1s", metavar="TIME",
        help="Extra time for in-flight k6 iterations to finish (default: 1s).",
    )
    execution.add_argument(
        "--threshold-mode", choices=["disabled", "strict"], default="disabled",
        help="disabled ignores WAF response status thresholds; strict enables failure and dropped-iteration thresholds (default: disabled).",
    )
    execution.add_argument(
        "--batch-max-duration", default="24h", metavar="TIME",
        help="Safety limit for one k6 batch process (default: 24h).",
    )
    execution.add_argument(
        "--preallocated-vus", type=int, metavar="N",
        help="k6 VUs allocated before arrival-rate traffic starts; mainly for high-rps.",
    )
    execution.add_argument(
        "--max-vus", type=int, metavar="N",
        help="Maximum VUs k6 may allocate; raise it when dropped_iterations appear.",
    )

    selection = parser.add_argument_group("case selection")
    selection.add_argument(
        "--start-index", type=int, default=0, metavar="N",
        help="Skip manifest entries before this zero-based source index (default: 0).",
    )
    selection.add_argument(
        "--limit", type=int, metavar="N",
        help="Run at most N matching cases after all filters are applied.",
    )
    selection.add_argument(
        "--case-id", metavar="ID",
        help="Run only the exact case_id.",
    )
    selection.add_argument(
        "--format", dest="formats", action="append", metavar="VALUE",
        help="Filter metadata.format. Repeat to allow multiple values.",
    )
    selection.add_argument(
        "--structure", dest="structures", action="append", metavar="VALUE",
        help="Filter metadata.structure. Repeat to allow multiple values.",
    )
    selection.add_argument(
        "--value-encoding", dest="value_encodings", action="append", metavar="VALUE",
        help="Filter metadata.value_encoding. Repeat to allow multiple values.",
    )
    selection.add_argument(
        "--charset", dest="charsets", action="append", metavar="VALUE",
        help="Filter metadata.charset. Repeat to allow multiple values.",
    )
    selection.add_argument(
        "--compression", dest="compressions", action="append", metavar="VALUE",
        help="Filter metadata.compression. Repeat to allow multiple values.",
    )
    selection.add_argument(
        "--validity", dest="validities", action="append",
        choices=["valid", "invalid", "invalid-compression"], metavar="VALUE",
        help="Filter metadata.validity. Repeat to allow multiple values.",
    )
    selection.add_argument(
        "--list", action="store_true",
        help="Print matching cases and exit without starting k6.",
    )

    output = parser.add_argument_group("output and shutdown")
    output.add_argument(
        "--print-request", choices=["none", "headers", "full"],
        help="Request details in CASE_START: none, headers, or full Base64 body. Default: headers in informative mode, otherwise none.",
    )
    output.add_argument(
        "--results-dir", default="results", metavar="DIR",
        help="Parent directory for run artifacts (default: results).",
    )
    output.add_argument(
        "--terminate-timeout", type=float, default=10.0, metavar="SECONDS",
        help="Wait after Ctrl+C before terminating k6 more aggressively (default: 10.0).",
    )
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
            index = 0
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    case = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
                if not isinstance(case, dict):
                    raise ValueError(f"JSONL line {line_number} is not an object")
                yield index, case
                index += 1
        return

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("legacy JSON manifest must be an array")
    for index, case in enumerate(data):
        if not isinstance(case, dict):
            raise ValueError(f"JSON array item {index} is not an object")
        yield index, case


def allowed(value: Any, values: list[str] | None) -> bool:
    return values is None or str(value) in values


def case_matches(case: dict[str, Any], args: argparse.Namespace) -> bool:
    if args.case_id and case.get("id") != args.case_id:
        return False
    metadata = case.get("metadata") or {}
    return all((
        allowed(metadata.get("format"), args.formats),
        allowed(metadata.get("structure"), args.structures),
        allowed(metadata.get("value_encoding"), args.value_encodings),
        allowed(metadata.get("charset"), args.charsets),
        allowed(metadata.get("compression"), args.compressions),
        allowed(metadata.get("validity"), args.validities),
    ))


def selected_cases(path: Path, manifest_format: str, args: argparse.Namespace) -> Iterator[tuple[int, dict[str, Any]]]:
    matched = 0
    for index, case in iter_manifest(path, manifest_format):
        if index < args.start_index or not case_matches(case, args):
            continue
        yield index, case
        matched += 1
        if args.limit is not None and matched >= args.limit:
            return


def batches(iterator: Iterator[tuple[int, dict[str, Any]]], size: int) -> Iterator[list[tuple[int, dict[str, Any]]]]:
    batch: list[tuple[int, dict[str, Any]]] = []
    for item in iterator:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def parse_k6_event(line: str) -> dict[str, Any] | None:
    candidates = [line.strip()]
    match = re.search(r'msg="(\{.*\})"(?:\s|$)', line)
    if match:
        try:
            candidates.append(bytes(match.group(1), "utf-8").decode("unicode_escape"))
        except UnicodeDecodeError:
            pass
    start, end = line.find("{"), line.rfind("}")
    if start >= 0 and end > start:
        candidates.append(line[start:end + 1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
            if isinstance(value, dict) and isinstance(value.get("event"), str):
                return value
        except json.JSONDecodeError:
            continue
    return None


def metric(summary: dict[str, Any], name: str, field: str) -> float | None:
    node = (summary.get("metrics") or {}).get(name)
    if not isinstance(node, dict):
        return None
    for container in (node.get("values"), node):
        if isinstance(container, dict) and isinstance(container.get(field), (int, float)):
            return float(container[field])
    return None


def compact_summary(path: Path) -> dict[str, float | None]:
    if not path.exists():
        return {}
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        "http_reqs": metric(summary, "http_reqs", "count"),
        "http_req_failed_rate": metric(summary, "http_req_failed", "rate"),
        "http_req_duration_p95_ms": metric(summary, "http_req_duration", "p(95)"),
        "http_req_duration_max_ms": metric(summary, "http_req_duration", "max"),
        "dropped_iterations": metric(summary, "dropped_iterations", "count"),
        "checks_rate": metric(summary, "checks", "rate"),
        "data_sent_bytes": metric(summary, "data_sent", "count"),
        "data_received_bytes": metric(summary, "data_received", "count"),
    }


def request_preview(case: dict[str, Any], mode: str) -> dict[str, Any] | None:
    if mode == "none":
        return None
    value = {
        "method": case.get("method"),
        "path": case.get("path"),
        "headers": case.get("headers"),
        "wire_body_size": case.get("wire_body_size"),
        "sha256": case.get("sha256"),
    }
    if mode == "full":
        value["body_base64"] = case.get("body_base64")
    return value


def terminate(process: subprocess.Popen[Any], timeout: float) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=max(0.1, timeout))
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main() -> int:
    args = parse_args()
    default_batch = 1 if args.mode == "informative" else 10 if args.mode == "high-rps" else 25
    batch_size = args.batch_size or default_batch
    print_mode = args.print_request or ("headers" if args.mode == "informative" else "none")

    if args.start_index < 0 or (args.limit is not None and args.limit < 1) or batch_size < 1 or args.rps < 1 or args.cooldown < 0:
        print("ERROR: invalid numeric option", file=sys.stderr)
        return 2

    payload_path = Path(args.payload_file).resolve()
    script_path = Path(args.k6_script).resolve()
    if not payload_path.is_file() or not script_path.is_file():
        print("ERROR: payload file or k6 script does not exist", file=sys.stderr)
        return 2
    manifest_format = detect_manifest_format(payload_path)

    if args.list:
        count = 0
        for index, case in selected_cases(payload_path, manifest_format, args):
            print(json.dumps({
                "index": index, "case_id": case.get("id"), "method": case.get("method"),
                "path": case.get("path"), "headers": case.get("headers"),
                "wire_body_size": case.get("wire_body_size"), "metadata": case.get("metadata"),
            }, ensure_ascii=False))
            count += 1
        print(f"Matched cases: {count}", file=sys.stderr)
        return 0 if count else 3

    if shutil.which("k6") is None:
        print("ERROR: k6 executable was not found in PATH", file=sys.stderr)
        return 2

    run_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    results = Path(args.results_dir) / run_id
    results.mkdir(parents=True)
    journal = results / "run.jsonl"
    active_case = results / "active_case.json"
    active_request = results / "active_request.json"
    archive = results / ("payloads.jsonl.gz" if manifest_format == "jsonl" else "payloads.json.gz")
    archive_manifest(payload_path, archive)

    config = vars(args) | {
        "run_id": run_id,
        "batch_size": batch_size,
        "print_request": print_mode,
        "payload_file": str(payload_path),
        "payload_manifest_format": manifest_format,
        "payload_manifest_sha256": file_sha256(payload_path),
        "archived_payload_file": str(archive),
        "k6_script": str(script_path),
    }
    atomic_json(results / "run_config.json", config)
    append_jsonl(journal, {"event": "RUN_START", "timestamp": utc_now(), **config})
    print(json.dumps({"event": "RUN_START", "run_id": run_id, "mode": args.mode, "batch_size": batch_size}, ensure_ascii=False), flush=True)

    completed = 0
    nonzero = 0
    process: subprocess.Popen[Any] | None = None
    current_event: dict[str, Any] | None = None
    temp_paths: tuple[Path, Path] | None = None

    try:
        with tempfile.TemporaryDirectory(prefix=f"waf-payload-{run_id}-") as temp_name:
            temp_dir = Path(temp_name)
            selected = selected_cases(payload_path, manifest_format, args)
            for batch_number, batch in enumerate(batches(selected, batch_size), 1):
                case_map: dict[int, dict[str, Any]] = {}
                payloads: list[dict[str, Any]] = []
                for index, case in batch:
                    item = dict(case)
                    item["_source_index"] = index
                    payloads.append(item)
                    case_map[index] = case

                case_file = temp_dir / "batch.json"
                atomic_json(case_file, payloads[0] if len(payloads) == 1 else payloads)
                summary_file = temp_dir / "summary.json"
                k6_log = temp_dir / "k6.log"
                temp_paths = (summary_file, k6_log)
                for path in temp_paths:
                    path.unlink(missing_ok=True)

                env = os.environ.copy()
                env.update({
                    "TARGET_URL": args.target,
                    "CASE_FILE": str(case_file),
                    "CASE_INDEX": str(batch[0][0]),
                    "RUN_ID": run_id,
                    "RUN_MODE": args.mode,
                    "RPS": str(args.rps),
                    "DURATION": args.duration,
                    "COOLDOWN": str(args.cooldown),
                    "GRACEFUL_STOP": args.graceful_stop,
                    "THRESHOLD_MODE": args.threshold_mode,
                    "BATCH_MAX_DURATION": args.batch_max_duration,
                })
                if args.preallocated_vus is not None:
                    env["PREALLOCATED_VUS"] = str(args.preallocated_vus)
                if args.max_vus is not None:
                    env["MAX_VUS"] = str(args.max_vus)

                batch_start = {
                    "event": "BATCH_START", "timestamp": utc_now(), "run_id": run_id,
                    "batch": batch_number, "mode": args.mode, "cases": len(batch),
                    "indices": [index for index, _ in batch],
                    "case_ids": [case.get("id") for _, case in batch],
                }
                append_jsonl(journal, batch_start)
                print(json.dumps(batch_start, ensure_ascii=False), flush=True)

                with k6_log.open("w", encoding="utf-8") as log:
                    process = subprocess.Popen(
                        ["k6", "run", "--summary-export", str(summary_file), str(script_path)],
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                    )
                    assert process.stdout is not None
                    for line in process.stdout:
                        log.write(line)
                        log.flush()
                        event = parse_k6_event(line)
                        if not event:
                            continue
                        event_type = event.get("event")
                        if event_type == "CASE_START":
                            index = int(event["payload_index"])
                            case = case_map.get(index)
                            current_event = event
                            record = {
                                "event": "CASE_START", "timestamp": utc_now(), "run_id": run_id,
                                "mode": args.mode, "index": index, "case_id": event.get("payload_id"),
                                "sha256": event.get("sha256"), "wire_body_size": event.get("wire_body_size"),
                                "metadata": event.get("metadata"), "target_rps": event.get("target_rps"),
                                "scheduled_duration": event.get("scheduled_duration"),
                                "request_file": str(active_request),
                            }
                            if case is not None:
                                atomic_json(active_request, {"index": index, "case_id": case.get("id"), "request": case})
                                preview = request_preview(case, print_mode)
                                if preview is not None:
                                    record["request"] = preview
                            atomic_json(active_case, {"run_id": run_id, "active": record, "completed": False})
                            append_jsonl(journal, record)
                            print(json.dumps(record, ensure_ascii=False), flush=True)
                        elif event_type == "CASE_END":
                            record = {
                                "event": "CASE_END", "timestamp": utc_now(), "run_id": run_id,
                                "mode": args.mode, "index": event.get("payload_index"),
                                "case_id": event.get("payload_id"), "requests": event.get("requests"),
                                "elapsed_seconds": event.get("elapsed_seconds"),
                                "target_rps": event.get("target_rps"),
                                "scheduled_duration": event.get("scheduled_duration"),
                            }
                            append_jsonl(journal, record)
                            print(json.dumps(record, ensure_ascii=False), flush=True)
                            completed += 1
                            current_event = None
                            atomic_json(active_case, {"run_id": run_id, "active": None, "last_completed": record, "completed": False})
                    exit_code = process.wait()
                    process = None

                nonzero += int(exit_code != 0)
                batch_end = {
                    "event": "BATCH_END", "timestamp": utc_now(), "run_id": run_id,
                    "batch": batch_number, "mode": args.mode, "exit_code": exit_code,
                    "metrics": compact_summary(summary_file),
                }
                append_jsonl(journal, batch_end)
                print(json.dumps(batch_end, ensure_ascii=False), flush=True)

    except KeyboardInterrupt:
        if process is not None:
            terminate(process, args.terminate_timeout)
        interrupted = {
            "event": "RUN_INTERRUPTED", "timestamp": utc_now(), "run_id": run_id,
            "mode": args.mode, "reason": "SIGINT",
            "active_index": current_event.get("payload_index") if current_event else None,
            "active_case_id": current_event.get("payload_id") if current_event else None,
            "active_request_file": str(active_request) if active_request.exists() else None,
        }
        append_jsonl(journal, interrupted)
        atomic_json(active_case, {"run_id": run_id, "active": current_event, "interrupted_at": interrupted["timestamp"], "completed": False})
        interrupted_dir = results / "interrupted"
        interrupted_dir.mkdir(exist_ok=True)
        if active_request.exists():
            shutil.copy2(active_request, interrupted_dir / "request.json")
        if temp_paths:
            for source, name in zip(temp_paths, ("k6-summary.json", "k6.log")):
                if source.exists():
                    shutil.copy2(source, interrupted_dir / name)
        print(json.dumps(interrupted, ensure_ascii=False), flush=True)
        print(f"Interrupted results: {results}")
        return 130
    except (ValueError, OSError) as exc:
        append_jsonl(journal, {"event": "RUN_ERROR", "timestamp": utc_now(), "run_id": run_id, "error": str(exc)})
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if completed == 0:
        atomic_json(active_case, {"run_id": run_id, "active": None, "completed": True, "no_matches": True})
        append_jsonl(journal, {"event": "RUN_END", "timestamp": utc_now(), "run_id": run_id, "completed_cases": 0, "no_matches": True})
        return 3

    atomic_json(active_case, {"run_id": run_id, "active": None, "completed": True, "completed_at": utc_now()})
    append_jsonl(journal, {"event": "RUN_END", "timestamp": utc_now(), "run_id": run_id, "completed_cases": completed, "nonzero_exit_codes": nonzero})
    print(f"Results: {results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
