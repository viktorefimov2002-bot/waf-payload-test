#!/usr/bin/env python3
"""Decode body_base64 fields from a JSON/JSONL payload manifest without altering the bytes."""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any, Iterator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Decode each body_base64 value and write a JSON array in which the exact "
            "request body is stored as body_bytes (an array of integers from 0 to 255). "
            "No decompression, charset conversion, or other body transformation is performed."
        )
    )
    parser.add_argument("input", help="Source manifest in JSON-array or JSONL format")
    parser.add_argument(
        "-o",
        "--output",
        default="full_requests.json",
        help="Destination JSON file (default: full_requests.json)",
    )
    return parser.parse_args()


def detect_format(path: Path) -> str:
    with path.open("r", encoding="utf-8") as handle:
        while True:
            char = handle.read(1)
            if not char:
                raise ValueError("input manifest is empty")
            if not char.isspace():
                return "json" if char == "[" else "jsonl"


def iter_cases(path: Path, input_format: str) -> Iterator[tuple[int, dict[str, Any]]]:
    if input_format == "jsonl":
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

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("JSON input must contain an array of case objects")
    for index, case in enumerate(data):
        if not isinstance(case, dict):
            raise ValueError(f"JSON item {index} is not an object")
        yield index, case


def decode_case(index: int, case: dict[str, Any]) -> dict[str, Any]:
    encoded = case.get("body_base64")
    if not isinstance(encoded, str):
        raise ValueError(f"case {index} does not contain a string body_base64 field")
    try:
        body = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        case_id = case.get("id", "<unknown>")
        raise ValueError(f"invalid body_base64 in case {index} ({case_id}): {exc}") from exc

    decoded = dict(case)
    decoded.pop("body_base64", None)
    decoded["body_bytes"] = list(body)
    return decoded


def main() -> int:
    args = parse_args()
    source = Path(args.input)
    destination = Path(args.output)

    if not source.is_file():
        print(f"ERROR: input file does not exist: {source}", file=sys.stderr)
        return 2
    if source.resolve() == destination.resolve():
        print("ERROR: input and output paths must be different", file=sys.stderr)
        return 2

    try:
        input_format = detect_format(source)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        destination.parent.mkdir(parents=True, exist_ok=True)

        count = 0
        with temporary.open("w", encoding="utf-8") as output:
            output.write("[\n")
            first = True
            for index, case in iter_cases(source, input_format):
                decoded = decode_case(index, case)
                if not first:
                    output.write(",\n")
                json.dump(decoded, output, ensure_ascii=False, separators=(",", ":"))
                first = False
                count += 1
            output.write("\n]\n")
            output.flush()

        temporary.replace(destination)
    except (OSError, ValueError) as exc:
        try:
            temporary.unlink(missing_ok=True)
        except UnboundLocalError:
            pass
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"Decoded {count} request bodies into {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
