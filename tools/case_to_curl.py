#!/usr/bin/env python3
"""Build and optionally execute a byte-exact curl request for one manifest case."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urljoin


class CaseCurlError(RuntimeError):
    """Raised when a manifest case cannot be converted to a curl request."""


def iter_cases(path: Path) -> Iterator[dict[str, Any]]:
    """Yield cases from JSONL or legacy JSON-array manifests."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            first = ""
            while True:
                char = handle.read(1)
                if not char:
                    raise CaseCurlError(f"manifest is empty: {path}")
                if not char.isspace():
                    first = char
                    break

        if first == "[":
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise CaseCurlError("legacy JSON manifest must contain an array")
            for index, case in enumerate(data):
                if not isinstance(case, dict):
                    raise CaseCurlError(f"manifest item {index} is not an object")
                yield case
            return

        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    case = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise CaseCurlError(f"invalid JSONL at line {line_number}: {exc}") from exc
                if not isinstance(case, dict):
                    raise CaseCurlError(f"JSONL line {line_number} is not an object")
                yield case
    except OSError as exc:
        raise CaseCurlError(f"cannot read manifest {path}: {exc}") from exc


def find_case(path: Path, case_id: str) -> dict[str, Any]:
    for case in iter_cases(path):
        if case.get("id") == case_id:
            return case
    raise CaseCurlError(f"case not found: {case_id}")


def decode_wire_body(case: dict[str, Any]) -> bytes:
    encoded = case.get("body_base64")
    if not isinstance(encoded, str) or not encoded:
        raise CaseCurlError("case does not contain a non-empty body_base64 field")
    try:
        body = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise CaseCurlError("body_base64 is not valid Base64") from exc

    expected_size = case.get("wire_body_size")
    if isinstance(expected_size, int) and len(body) != expected_size:
        raise CaseCurlError(
            f"decoded body size mismatch: manifest={expected_size}, actual={len(body)}"
        )
    expected_sha = case.get("sha256")
    actual_sha = hashlib.sha256(body).hexdigest()
    if isinstance(expected_sha, str) and expected_sha and actual_sha != expected_sha:
        raise CaseCurlError(
            f"decoded body SHA-256 mismatch: manifest={expected_sha}, actual={actual_sha}"
        )
    return body


def request_url(target: str, path: str) -> str:
    base = target.rstrip("/") + "/"
    return urljoin(base, path.lstrip("/"))


def normalized_headers(case: dict[str, Any], *, include_debug_headers: bool) -> list[tuple[str, str]]:
    raw = case.get("headers") or {}
    if not isinstance(raw, dict):
        raise CaseCurlError("case.headers must be an object")

    headers: list[tuple[str, str]] = []
    seen = set()
    for name, value in raw.items():
        lower = str(name).lower()
        # curl calculates Content-Length from the exact file body. Keeping a stale value is unsafe.
        if lower in {"content-length", "host"}:
            continue
        headers.append((str(name), str(value)))
        seen.add(lower)

    if include_debug_headers:
        case_id = str(case.get("id") or "unknown")
        if "x-waf-test-case-id" not in seen:
            headers.append(("X-WAF-Test-Case-ID", case_id))
        if "x-waf-test-sequence" not in seen:
            headers.append(("X-WAF-Test-Sequence", case_id))
        if "x-waf-test-source" not in seen:
            headers.append(("X-WAF-Test-Source", "manual-curl-debug"))
    return headers


def build_curl_args(
    case: dict[str, Any],
    *,
    target: str,
    body_file: Path,
    insecure: bool,
    include_debug_headers: bool,
    timeout: float | None,
    output_headers: bool,
) -> list[str]:
    method = str(case.get("method") or "POST")
    path = str(case.get("path") or "/")
    args = ["curl", "--verbose", "--request", method]
    if insecure:
        args.append("--insecure")
    if output_headers:
        args.append("--include")
    if timeout is not None:
        args.extend(["--max-time", str(timeout)])
    for name, value in normalized_headers(case, include_debug_headers=include_debug_headers):
        args.extend(["--header", f"{name}: {value}"])
    args.extend(["--data-binary", f"@{body_file}", request_url(target, path)])
    return args


def shell_command(args: list[str]) -> str:
    return " \\\n  ".join(shlex.quote(value) for value in args)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Extract one generated case and print or execute a byte-exact curl command.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    result.add_argument("case_id", help="Exact case id from the payload manifest")
    result.add_argument("--manifest", default="payloads/baseline-full.jsonl")
    result.add_argument("--target", required=True, help="Base target URL")
    result.add_argument(
        "--output-dir",
        default="debug-artifacts/curl-cases",
        help="Directory for extracted wire bodies and metadata",
    )
    result.add_argument("--execute", action="store_true", help="Execute curl after printing it")
    result.add_argument("--insecure", action=argparse.BooleanOptionalAction, default=True)
    result.add_argument("--debug-headers", action=argparse.BooleanOptionalAction, default=True)
    result.add_argument("--timeout", type=float, default=30.0)
    result.add_argument("--include-response-headers", action=argparse.BooleanOptionalAction, default=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        manifest = Path(args.manifest)
        case = find_case(manifest, args.case_id)
        body = decode_wire_body(case)

        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_id = "".join(char if char.isalnum() or char in "-_." else "_" for char in args.case_id)
        body_file = output_dir / f"{safe_id}.wire-body.bin"
        metadata_file = output_dir / f"{safe_id}.json"
        body_file.write_bytes(body)
        metadata_file.write_text(json.dumps(case, ensure_ascii=False, indent=2), encoding="utf-8")

        curl_args = build_curl_args(
            case,
            target=args.target,
            body_file=body_file,
            insecure=args.insecure,
            include_debug_headers=args.debug_headers,
            timeout=args.timeout,
            output_headers=args.include_response_headers,
        )
        print(f"Case: {args.case_id}", file=sys.stderr)
        print(f"Manifest: {manifest}", file=sys.stderr)
        print(f"Wire body: {body_file} ({len(body)} bytes)", file=sys.stderr)
        print(f"Metadata: {metadata_file}", file=sys.stderr)
        print(f"SHA-256: {hashlib.sha256(body).hexdigest()}", file=sys.stderr)
        print(shell_command(curl_args))

        if not args.execute:
            return 0
        completed = subprocess.run(curl_args, check=False)
        return completed.returncode
    except CaseCurlError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
