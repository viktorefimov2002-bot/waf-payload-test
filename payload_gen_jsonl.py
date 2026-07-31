#!/usr/bin/env python3
"""Generate JSONL manifests through a profile-aware CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Iterable

PROFILE_ALIASES = {
    "phase1": "parser-stress",
    "phase2": "decompression-stress",
}
PROFILE_DESCRIPTIONS = {
    "baseline": "Representative coverage of ordinary request-body parsing paths.",
    "parser-stress": "Parser, allocator and normalization stress using dedicated edge-case structures.",
    "decompression-stress": "Controlled decompression stress using specialized compressed streams.",
}
ALL_PROFILE_NAMES = [*PROFILE_DESCRIPTIONS, *PROFILE_ALIASES]


def canonical_profile(profile: str) -> str:
    return PROFILE_ALIASES.get(profile, profile)


def detect_profile(argv: list[str]) -> tuple[str, str]:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--stress-profile", choices=ALL_PROFILE_NAMES, default="baseline")
    namespace, _ = pre_parser.parse_known_args(argv)
    requested = namespace.stress_profile
    return requested, canonical_profile(requested)


def rewrite_profile_argument(requested: str, canonical: str) -> None:
    if requested == canonical:
        return
    print(
        f"Warning: stress profile '{requested}' is deprecated; use '{canonical}'.",
        file=sys.stderr,
    )
    for index, value in enumerate(sys.argv[:-1]):
        if value == "--stress-profile":
            sys.argv[index + 1] = canonical
            return


def load_profile(
    profile: str,
) -> tuple[Callable[[], argparse.Namespace], Callable[[argparse.Namespace], Iterable[dict[str, Any]]]]:
    if profile == "decompression-stress":
        from _decompression_stress_profile import iter_cases, parse_args

        return parse_args, iter_cases
    if profile == "parser-stress":
        from _parser_stress_profile import iter_cases, parse_args

        return parse_args, iter_cases

    from _structural_profile import iter_cases, parse_args

    return lambda: parse_args("baseline"), iter_cases


def main() -> int:
    requested, profile = detect_profile(sys.argv[1:])
    rewrite_profile_argument(requested, profile)
    parse_args, iter_cases = load_profile(profile)

    if "--output" not in sys.argv:
        sys.argv.extend(["--output", f"payloads_{profile.replace('-', '_')}.jsonl"])

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
                metadata["stress_profile"] = profile
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
