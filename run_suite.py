#!/usr/bin/env python3
"""Run streamed WAF payload cases through k6 using CLI options or strict YAML configs."""
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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run byte-exact WAF payload cases through k6.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--config", help="Strict YAML run configuration")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--target", metavar="URL")
    parser.add_argument("--payload-file")
    parser.add_argument("--k6-script")
    parser.add_argument("--mode", choices=["fast", "informative", "high-rps"])
    parser.add_argument("--batch-size", type=int)
    parser.add_argument("--rps", type=int)
    parser.add_argument("--duration")
    parser.add_argument("--cooldown", type=float)
    parser.add_argument("--graceful-stop")
    parser.add_argument("--threshold-mode", choices=["disabled", "strict"])
    parser.add_argument("--batch-max-duration")
    parser.add_argument("--preallocated-vus", type=int)
    parser.add_argument("--max-vus", type=int)
    parser.add_argument("--lanes", type=int)
    parser.add_argument("--max-total-rps", type=int)
    parser.add_argument("--abort-on-overload", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--max-dropped-iterations", type=int)
    parser.add_argument("--max-http-req-duration-p95-ms", type=float)
    parser.add_argument("--overload-delay")
    parser.add_argument("--stop-run-on-batch-abort", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--start-index", type=int)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--case-id")
    parser.add_argument("--format", dest="formats", action="append")
    parser.add_argument("--structure", dest="structures", action="append")
    parser.add_argument("--value-encoding", dest="value_encodings", action="append")
    parser.add_argument("--charset", dest="charsets", action="append")
    parser.add_argument("--compression", dest="compressions", action="append")
    parser.add_argument("--validity", dest="validities", action="append")
    parser.add_argument("--list", action="store_true", default=None)
    parser.add_argument("--print-request", choices=["none", "headers", "full"])
    parser.add_argument("--results-dir")
    parser.add_argument("--terminate-timeout", type=float)
    parser.add_argument("--lane-journals", action=argparse.BooleanOptionalAction, default=None)
    return parser


def cli_defaults(cli: argparse.Namespace) -> argparse.Namespace:
    values = vars(cli).copy()
    values.update({
        "payload_file": cli.payload_file or "payloads/baseline-smoke.jsonl",
        "k6_script": cli.k6_script or "k6_run_payloads.js",
        "mode": cli.mode or "fast",
        "rps": cli.rps or 10,
        "duration": cli.duration or "30s",
        "cooldown": 5.0 if cli.cooldown is None else cli.cooldown,
        "graceful_stop": cli.graceful_stop or "1s",
        "threshold_mode": cli.threshold_mode or "disabled",
        "batch_max_duration": cli.batch_max_duration or "24h",
        "lanes": cli.lanes or 1,
        "abort_on_overload": bool(cli.abort_on_overload),
        "max_dropped_iterations": 0 if cli.max_dropped_iterations is None else cli.max_dropped_iterations,
        "max_http_req_duration_p95_ms": 0.0 if cli.max_http_req_duration_p95_ms is None else cli.max_http_req_duration_p95_ms,
        "overload_delay": cli.overload_delay or "5s",
        "stop_run_on_batch_abort": True if cli.stop_run_on_batch_abort is None else cli.stop_run_on_batch_abort,
        "start_index": cli.start_index or 0,
        "list": bool(cli.list),
        "results_dir": cli.results_dir or "results",
        "terminate_timeout": 10.0 if cli.terminate_timeout is None else cli.terminate_timeout,
        "lane_journals": True if cli.lane_journals is None else cli.lane_journals,
        "run_config_file": None,
        "run_config_name": None,
    })
    return argparse.Namespace(**values)


def apply_cli_overrides(args: argparse.Namespace, cli: argparse.Namespace) -> argparse.Namespace:
    names = (
        "target", "payload_file", "k6_script", "mode", "batch_size", "rps", "duration",
        "cooldown", "graceful_stop", "threshold_mode", "batch_max_duration",
        "preallocated_vus", "max_vus", "lanes", "max_total_rps",
        "abort_on_overload", "max_dropped_iterations", "max_http_req_duration_p95_ms",
        "overload_delay", "stop_run_on_batch_abort", "start_index", "limit", "case_id",
        "formats", "structures", "value_encodings", "charsets", "compressions", "validities",
        "list", "print_request", "results_dir", "terminate_timeout", "lane_journals",
    )
    for name in names:
        value = getattr(cli, name)
        if value is not None:
            setattr(args, name, value)
    return args


def parse_args() -> tuple[argparse.Namespace, bool]:
    parser = cli_parser()
    cli = parser.parse_args()
    if not cli.config:
        args = cli_defaults(cli)
        if not args.target:
            parser.error("--target is required when --config is not used")
        return args, cli.validate_only
    from modules.run_config import RunConfigError, load_run_config
    try:
        args = load_run_config(cli.config)
        args = apply_cli_overrides(args, cli)
    except RunConfigError as exc:
        parser.error(str(exc))
    if args.case_id:
        args.batch_size = 1
        args.lanes = 1
        if args.max_total_rps is not None and args.rps > args.max_total_rps:
            parser.error("single-case RPS exceeds max_total_rps")
    return args, cli.validate_only


def print_summary(args: argparse.Namespace) -> None:
    default_batch = 1 if args.mode == "informative" else 10 if args.mode == "high-rps" else 25
    print(f"Mode: {args.mode}")
    print(f"Target: {args.target}")
    print(f"Payload file: {args.payload_file}")
    print(f"k6 script: {args.k6_script}")
    print(f"Batch size: {args.batch_size or default_batch}")
    print(f"RPS per active case: {args.rps}")
    print(f"Parallel lanes: {args.lanes}")
    print(f"Maximum active RPS: {args.rps * args.lanes}")
    print(f"Duration: {args.duration}")
    print(f"Graceful stop: {args.graceful_stop}")
    print(f"Cooldown per lane: {args.cooldown}")
    print(f"Abort on overload: {args.abort_on_overload}")
    if args.abort_on_overload:
        print(f"Maximum dropped iterations per batch: {args.max_dropped_iterations}")
        print(f"Maximum batch p95: {args.max_http_req_duration_p95_ms} ms")
    print(f"Results dir: {args.results_dir}")


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


def load_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def metric_from(summary: dict[str, Any], name: str, field: str) -> float | None:
    node = (summary.get("metrics") or {}).get(name)
    if not isinstance(node, dict):
        return None
    for container in (node.get("values"), node):
        if isinstance(container, dict) and isinstance(container.get(field), (int, float)):
            return float(container[field])
    return None


def compact_summary(summary: dict[str, Any]) -> dict[str, float | None]:
    return {
        "http_reqs": metric_from(summary, "http_reqs", "count"),
        "http_req_failed_rate": metric_from(summary, "http_req_failed", "rate"),
        "http_req_duration_p95_ms": metric_from(summary, "http_req_duration", "p(95)"),
        "http_req_duration_max_ms": metric_from(summary, "http_req_duration", "max"),
        "dropped_iterations": metric_from(summary, "dropped_iterations", "count"),
        "checks_rate": metric_from(summary, "checks", "rate"),
    }


def per_case_metrics(summary: dict[str, Any], batch: list[tuple[int, dict[str, Any]]], lanes: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for offset, (index, case) in enumerate(batch):
        scenario = f"payload_{offset}"
        records.append({
            "index": index,
            "case_id": case.get("id"),
            "lane": offset % lanes,
            "scenario": scenario,
            "http_reqs": metric_from(summary, f"http_reqs{{scenario:{scenario}}}", "count"),
            "iterations": metric_from(summary, f"iterations{{scenario:{scenario}}}", "count"),
            "dropped_iterations": metric_from(summary, f"dropped_iterations{{scenario:{scenario}}}", "count") or 0.0,
            "http_req_failed_rate": metric_from(summary, f"http_req_failed{{scenario:{scenario}}}", "rate"),
            "http_req_duration_p95_ms": metric_from(summary, f"http_req_duration{{scenario:{scenario}}}", "p(95)"),
            "http_req_duration_max_ms": metric_from(summary, f"http_req_duration{{scenario:{scenario}}}", "max"),
        })
    return records


def overload_reason(args: argparse.Namespace, metrics: dict[str, float | None]) -> str | None:
    if not args.abort_on_overload:
        return None
    dropped = metrics.get("dropped_iterations") or 0.0
    if dropped > args.max_dropped_iterations:
        return f"dropped_iterations={dropped:g} exceeds {args.max_dropped_iterations}"
    p95 = metrics.get("http_req_duration_p95_ms")
    if args.max_http_req_duration_p95_ms > 0 and p95 is not None and p95 >= args.max_http_req_duration_p95_ms:
        return f"http_req_duration p95={p95:g}ms exceeds {args.max_http_req_duration_p95_ms:g}ms"
    return None


def request_preview(case: dict[str, Any], mode: str) -> dict[str, Any] | None:
    if mode == "none":
        return None
    value = {key: case.get(key) for key in ("method", "path", "headers", "wire_body_size", "sha256")}
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
    args, validate_only = parse_args()
    default_batch = 1 if args.mode == "informative" else 10 if args.mode == "high-rps" else 25
    batch_size = args.batch_size or default_batch
    print_mode = args.print_request or ("headers" if args.mode == "informative" else "none")
    if (
        args.start_index < 0 or (args.limit is not None and args.limit < 1) or batch_size < 1
        or args.rps < 1 or args.cooldown < 0 or args.lanes < 1
        or args.max_dropped_iterations < 0 or args.max_http_req_duration_p95_ms < 0
    ):
        print("ERROR: invalid numeric option", file=sys.stderr)
        return 2
    if args.mode != "high-rps" and args.lanes != 1:
        print("ERROR: parallel lanes are supported only in high-rps mode", file=sys.stderr)
        return 2
    if args.max_total_rps is not None and args.rps * args.lanes > args.max_total_rps:
        print("ERROR: rps * lanes exceeds max_total_rps", file=sys.stderr)
        return 2

    payload_path = Path(args.payload_file).resolve()
    script_path = Path(args.k6_script).resolve()
    if not payload_path.is_file() or not script_path.is_file():
        print("ERROR: payload file or k6 script does not exist", file=sys.stderr)
        return 2
    manifest_format = detect_manifest_format(payload_path)
    print_summary(args)
    if validate_only:
        print(f"Manifest format: {manifest_format}")
        return 0
    if args.list:
        count = 0
        for index, case in selected_cases(payload_path, manifest_format, args):
            print(json.dumps({"index": index, "case_id": case.get("id"), "metadata": case.get("metadata")}, ensure_ascii=False))
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
    case_results = results / "case_results.jsonl"
    active_cases_file = results / "active_cases.json"
    active_requests_dir = results / "active_requests"
    lanes_dir = results / "lanes"
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
        "rps_scope": "per-case",
        "maximum_active_rps": args.rps * args.lanes,
    }
    atomic_json(results / "run_config.json", config)
    append_jsonl(journal, {"event": "RUN_START", "timestamp": utc_now(), **config})
    print(json.dumps({
        "event": "RUN_START", "run_id": run_id, "mode": args.mode,
        "batch_size": batch_size, "lanes": args.lanes,
        "rps_per_case": args.rps, "maximum_active_rps": args.rps * args.lanes,
    }), flush=True)

    completed = 0
    nonzero = 0
    overloaded = False
    process: subprocess.Popen[Any] | None = None
    active_cases: dict[int, dict[str, Any]] = {}

    def write_active_cases() -> None:
        atomic_json(active_cases_file, {
            "run_id": run_id,
            "active": {str(lane): record for lane, record in sorted(active_cases.items())},
            "active_count": len(active_cases),
        })

    def write_event(record: dict[str, Any]) -> None:
        append_jsonl(journal, record)
        lane = record.get("lane")
        if args.lane_journals and isinstance(lane, int):
            append_jsonl(lanes_dir / f"lane-{lane:03d}.jsonl", record)
        print(json.dumps(record, ensure_ascii=False), flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix=f"waf-payload-{run_id}-") as temp_name:
            temp_dir = Path(temp_name)
            for batch_number, batch in enumerate(batches(selected_cases(payload_path, manifest_format, args), batch_size), 1):
                case_map: dict[int, dict[str, Any]] = {}
                payloads: list[dict[str, Any]] = []
                for offset, (index, case) in enumerate(batch):
                    item = dict(case)
                    item["_source_index"] = index
                    item["_lane"] = offset % args.lanes
                    payloads.append(item)
                    case_map[index] = case
                case_file = temp_dir / "batch.json"
                atomic_json(case_file, payloads[0] if len(payloads) == 1 else payloads)
                summary_file = temp_dir / "summary.json"
                k6_log = temp_dir / "k6.log"
                summary_file.unlink(missing_ok=True)
                k6_log.unlink(missing_ok=True)
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
                    "PARALLEL_LANES": str(args.lanes),
                    "ABORT_ON_OVERLOAD": str(args.abort_on_overload).lower(),
                    "MAX_DROPPED_ITERATIONS": str(args.max_dropped_iterations),
                    "MAX_HTTP_REQ_DURATION_P95_MS": str(args.max_http_req_duration_p95_ms),
                    "OVERLOAD_DELAY": args.overload_delay,
                })
                if args.preallocated_vus is not None:
                    env["PREALLOCATED_VUS"] = str(args.preallocated_vus)
                if args.max_vus is not None:
                    env["MAX_VUS"] = str(args.max_vus)
                batch_start = {
                    "event": "BATCH_START", "timestamp": utc_now(), "run_id": run_id,
                    "batch": batch_number, "mode": args.mode, "cases": len(batch),
                    "lanes": min(args.lanes, len(batch)),
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
                            lane = int(event.get("lane", 0))
                            case = case_map.get(index)
                            request_file = active_requests_dir / f"lane-{lane:03d}.json"
                            record = {
                                "event": "CASE_START", "timestamp": utc_now(), "run_id": run_id,
                                "mode": args.mode, "lane": lane, "index": index,
                                "case_id": event.get("payload_id"), "sha256": event.get("sha256"),
                                "wire_body_size": event.get("wire_body_size"), "metadata": event.get("metadata"),
                                "target_rps": event.get("target_rps"), "scheduled_duration": event.get("scheduled_duration"),
                                "request_file": str(request_file),
                            }
                            if case is not None:
                                atomic_json(request_file, {"lane": lane, "index": index, "case_id": case.get("id"), "request": case})
                                preview = request_preview(case, print_mode)
                                if preview is not None:
                                    record["request"] = preview
                            active_cases[lane] = record
                            write_active_cases()
                            write_event(record)
                        elif event_type == "CASE_END":
                            lane = int(event.get("lane", 0))
                            record = {
                                "event": "CASE_END", "timestamp": utc_now(), "run_id": run_id,
                                "mode": args.mode, "lane": lane, "index": event.get("payload_index"),
                                "case_id": event.get("payload_id"), "requests": event.get("requests"),
                                "expected_requests": event.get("expected_requests"),
                                "elapsed_seconds": event.get("elapsed_seconds"),
                                "target_rps": event.get("target_rps"), "scheduled_duration": event.get("scheduled_duration"),
                            }
                            write_event(record)
                            append_jsonl(case_results, record)
                            completed += 1
                            active_cases.pop(lane, None)
                            write_active_cases()
                    exit_code = process.wait()
                    process = None
                nonzero += int(exit_code != 0)
                summary = load_summary(summary_file)
                metrics = compact_summary(summary)
                for case_metric in per_case_metrics(summary, batch, args.lanes) if args.mode == "high-rps" else []:
                    record = {
                        "event": "CASE_METRICS", "timestamp": utc_now(), "run_id": run_id,
                        "batch": batch_number, **case_metric,
                    }
                    append_jsonl(case_results, record)
                    append_jsonl(journal, record)
                reason = overload_reason(args, metrics)
                batch_end = {
                    "event": "BATCH_END", "timestamp": utc_now(), "run_id": run_id,
                    "batch": batch_number, "mode": args.mode, "exit_code": exit_code,
                    "lanes": min(args.lanes, len(batch)), "metrics": metrics,
                    "overloaded": reason is not None, "overload_reason": reason,
                }
                append_jsonl(journal, batch_end)
                print(json.dumps(batch_end, ensure_ascii=False), flush=True)
                shutil.copy2(k6_log, results / f"k6-batch-{batch_number:04d}.log")
                if summary_file.exists():
                    shutil.copy2(summary_file, results / f"summary-batch-{batch_number:04d}.json")
                if reason is not None and args.stop_run_on_batch_abort:
                    overloaded = True
                    abort_record = {
                        "event": "RUN_ABORTED_OVERLOAD", "timestamp": utc_now(), "run_id": run_id,
                        "batch": batch_number, "reason": reason, "metrics": metrics,
                        "case_ids": [case.get("id") for _, case in batch],
                    }
                    append_jsonl(journal, abort_record)
                    print(json.dumps(abort_record, ensure_ascii=False), flush=True)
                    break
    except KeyboardInterrupt:
        if process is not None:
            terminate(process, args.terminate_timeout)
        interrupted = {
            "event": "RUN_INTERRUPTED", "timestamp": utc_now(), "run_id": run_id,
            "mode": args.mode, "reason": "SIGINT",
            "active_cases": {str(lane): record for lane, record in sorted(active_cases.items())},
        }
        append_jsonl(journal, interrupted)
        print(json.dumps(interrupted, ensure_ascii=False), flush=True)
        return 130
    except (ValueError, OSError) as exc:
        append_jsonl(journal, {"event": "RUN_ERROR", "timestamp": utc_now(), "run_id": run_id, "error": str(exc)})
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if completed == 0:
        append_jsonl(journal, {"event": "RUN_END", "timestamp": utc_now(), "run_id": run_id, "completed_cases": 0, "no_matches": True})
        return 3
    append_jsonl(journal, {
        "event": "RUN_END", "timestamp": utc_now(), "run_id": run_id,
        "completed_cases": completed, "nonzero_exit_codes": nonzero,
        "lanes": args.lanes, "rps_per_case": args.rps, "overloaded": overloaded,
    })
    print(f"Results: {results}")
    return 4 if overloaded else 0


if __name__ == "__main__":
    raise SystemExit(main())
