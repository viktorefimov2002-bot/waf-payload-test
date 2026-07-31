#!/usr/bin/env python3
"""Generate JSONL manifests through a profile-aware CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Iterable


def detect_profile(argv: list[str]) -> str:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument(
        "--stress-profile",
        choices=["baseline", "phase1", "phase2"],
        default="baseline",
    )
    namespace, _ = pre_parser.parse_known_args(argv)
    return namespace.stress_profile


def load_profile(profile: str) -> tuple[Callable[[], argparse.Namespace], Callable[[argparse.Namespace], Iterable[dict[str, Any]]]]:
    if profile == "phase2":
        from _decompression_profile import iter_cases, parse_args

        return parse_args, iter_cases

    from payload_gen import iter_cases, parse_args

    return parse_args, iter_cases


def main() -> int:
    profile = detect_profile(sys.argv[1:])
    parse_args, iter_cases = load_profile(profile)

    if "--output" not in sys.argv:
        default_output = "payloads_phase2.jsonl" if profile == "phase2" else "payloads.jsonl"
        sys.argv.extend(["--output", default_output])

    args = parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")

    total = 0
    valid = 0
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            for case in iter_cases(args):
                handle.write(json.dumps(case, ensure_ascii=False, separators=(",", ":")) + "\n")
                total += 1
                valid += int(case["metadata"]["validity"] == "valid")
        temporary.replace(output)
    except (OSError, RuntimeError, ValueError) as exc:
        temporary.unlink(missing_ok=True)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"Generated {total} cases in {output} ({valid} valid, {total - valid} invalid)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
