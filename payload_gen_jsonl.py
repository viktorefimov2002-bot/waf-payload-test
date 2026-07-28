#!/usr/bin/env python3
"""Stream payload cases from payload_gen.py into a JSONL manifest."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from payload_gen import iter_cases, parse_args


def main() -> None:
    if "--output" not in sys.argv:
        sys.argv.extend(["--output", "payloads.jsonl"])

    args = parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    valid = 0
    with output.open("w", encoding="utf-8") as handle:
        for case in iter_cases(args):
            handle.write(json.dumps(case, ensure_ascii=False, separators=(",", ":")) + "\n")
            total += 1
            valid += int(case["metadata"]["validity"] == "valid")

    print(f"Generated {total} cases in {output} ({valid} valid, {total - valid} invalid)")


if __name__ == "__main__":
    main()
