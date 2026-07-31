#!/usr/bin/env python3
"""Generate JSONL manifests through YAML configs or the legacy profile CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Iterable

PROFILE_ALIASES = {"phase1": "parser-stress", "phase2": "decompression-stress"}
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
    print(f"Warning: stress profile '{requested}' is deprecated; use '{canonical}'.", file=sys.stderr)
    for index, value in enumerate(sys.argv[:-1]):
        if value == "--stress-profile":
            sys.argv[index + 1] = canonical
            return


def load_profile(profile: str) -> tuple[Callable[[], argparse.Namespace], Callable[[argparse.Namespace], Iterable[dict[str, Any]]]]:
    if profile == "decompression-stress":
        from _decompression_stress_profile import iter_cases, parse_args
        return parse_args, iter_cases
    if profile == "parser-stress":
        from _parser_stress_profile import iter_cases, parse_args
        return parse_args, iter_cases
    from _structural_profile import iter_cases, parse_args
    return lambda: parse_args("baseline"), iter_cases


def iterator_for_config(profile: str) -> Callable[[argparse.Namespace], Iterable[dict[str, Any]]]:
    if profile == "decompression-stress":
        from _decompression_stress_profile import iter_cases
        return iter_cases
    if profile == "parser-stress":
        from _parser_stress_profile import iter_cases
        return iter_cases
    from _structural_profile import iter_cases
    return iter_cases


def config_cli(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate payloads from a strict profile-aware YAML config")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", help="Override output.file")
    parser.add_argument("--request-path", help="Override output.request_path")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def print_config_summary(config: Any) -> None:
    print(f"Config: {config.path}")
    print(f"Profile: {config.profile}")
    print(f"Output: {config.output_file}")
    print(f"Request path: {config.request_path}")
    print(f"Estimated cases (conservative): {config.estimated_cases}")
    print(f"Safety max cases: {config.safety['max_cases']}")
    print(f"Safety max wire body: {config.safety['max_wire_body_size']} bytes")
    print(f"Safety max decompressed body: {config.safety['max_decompressed_size']} bytes")


def generate(
    output: Path,
    profile: str,
    args: argparse.Namespace,
    iter_cases: Callable[[argparse.Namespace], Iterable[dict[str, Any]]],
    metadata_extra: dict[str, Any] | None = None,
    safety: dict[str, int] | None = None,
) -> tuple[int, int]:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    total = 0
    valid = 0
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            for case in iter_cases(args):
                total += 1
                if safety:
                    if total > safety["max_cases"]:
                        raise ValueError(f"generated case count exceeds safety.max_cases ({safety['max_cases']})")
                    wire_size = int(case.get("wire_body_size", 0))
                    decoded_size = int(case.get("metadata", {}).get("decompressed_size", case.get("serialized_size", 0)))
                    if wire_size > safety["max_wire_body_size"]:
                        raise ValueError(f"case {case.get('id')} wire body exceeds safety.max_wire_body_size")
                    if decoded_size > safety["max_decompressed_size"]:
                        raise ValueError(f"case {case.get('id')} decoded body exceeds safety.max_decompressed_size")
                metadata = case.setdefault("metadata", {})
                metadata["stress_profile"] = profile
                if metadata_extra:
                    metadata.update(metadata_extra)
                handle.write(json.dumps(case, ensure_ascii=False, separators=(",", ":")) + "\n")
                valid += int(metadata.get("validity") == "valid")
        temporary.replace(output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return total, valid


def main_config_mode() -> int:
    from _config_loader import ConfigError, load_config

    cli = config_cli(sys.argv[1:])
    try:
        config = load_config(cli.config, cli.output, cli.request_path)
        print_config_summary(config)
        if cli.validate_only or cli.dry_run:
            return 0
        if config.output_file.exists() and not config.overwrite:
            raise ConfigError(f"output already exists and output.overwrite is false: {config.output_file}")
        iterator = iterator_for_config(config.profile)
        metadata = {
            "suite_name": config.metadata.get("suite_name", config.path.stem),
            "suite_description": config.metadata.get("description", ""),
            "suite_tags": config.metadata.get("tags", []),
            "config_file": str(config.path),
        }
        total, valid = generate(config.output_file, config.profile, config.args, iterator, metadata, config.safety)
    except (ConfigError, OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Generated {total} {config.profile} cases in {config.output_file} ({valid} valid, {total - valid} invalid)")
    return 0


def main_legacy_mode() -> int:
    requested, profile = detect_profile(sys.argv[1:])
    rewrite_profile_argument(requested, profile)
    parse_args, iter_cases = load_profile(profile)
    if "--output" not in sys.argv:
        sys.argv.extend(["--output", f"payloads_{profile.replace('-', '_')}.jsonl"])
    try:
        args = parse_args()
        output = Path(args.output)
        total, valid = generate(output, profile, args, iter_cases)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Generated {total} {profile} cases in {output} ({valid} valid, {total - valid} invalid)")
    return 0


def main() -> int:
    return main_config_mode() if "--config" in sys.argv else main_legacy_mode()


if __name__ == "__main__":
    raise SystemExit(main())
