#!/usr/bin/env python3
"""Generate JSONL manifests through a profile-aware CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Iterable


PROFILE_DESCRIPTIONS = {
    "baseline": "Representative coverage of ordinary request-body parsing paths.",
    "phase1": "Parser and allocator stress using phase1-only structures.",
    "phase2": "Controlled decompression stress using specialized compressed streams.",
}


def detect_profile(argv: list[str]) -> str:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument(
        "--stress-profile",
        choices=list(PROFILE_DESCRIPTIONS),
        default="baseline",
    )
    namespace, _ = pre_parser.parse_known_args(argv)
    return namespace.stress_profile


def load_profile(
    profile: str,
) -> tuple[Callable[[], argparse.Namespace], Callable[[argparse.Namespace], Iterable[dict[str, Any]]]]:
    if profile == "phase2":
        from _decompression_profile import iter_cases, parse_args

        return parse_args, iter_cases

    from _structural_profile import iter_cases, parse_args

    return lambda: parse_args(profile), iter_cases


def main() -> int:
    profile = detect_profile(sys.argv[1:])
    parse_args, iter_cases = load_profile(profile)

    if "--output" not in sys.argv:
        sys.argv.extend(["--output", f"payloads_{profile}.jsonl"])

    args = parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")

    total = 0
    valid = 0
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            for case in iter_cases(args):
                metadata = case.setdefault("metadata", {})
                metadata.setdefault("stress_profile", profile)
                if profile == "phase2":
                    metadata.setdefault("profile_scope", "decompression-stress")
                handle.write(json.dumps(case, ensure_ascii=False, separators=(",", ":")) + "\n")
                total += 1
                valid += int(metadata.get("validity") == "valid")
        temporary.replace(output)
    except (OSError, RuntimeError, ValueError) as exc:
        temporary.unlink(missing_ok=True)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"Generated {total} {profile} cases in {output} ({valid} valid, {total - valid} invalid)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
