#!/usr/bin/env python3
"""Profile-specific CLI and case routing for baseline and phase1."""
from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from typing import Any

import payload_gen

PROFILE_DESCRIPTIONS = {
    "baseline": (
        "Representative request-body coverage: ordinary structures, common charsets, "
        "standard value encodings and ordinary single-layer compression."
    ),
    "phase1": (
        "Parser and allocator stress: phase1-only structures, boundary sizes, long names, "
        "escape-heavy values, charset faults and multipart edge cases."
    ),
}


def parse_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes"}


def structures_for_profile(profile: str, fmt: str) -> list[str]:
    if profile == "baseline":
        return list(payload_gen.BASE_STRUCTURES[fmt])
    if profile == "phase1":
        return list(payload_gen.PHASE1_STRUCTURES[fmt])
    raise ValueError(f"unsupported structural profile: {profile}")


def build_parser(profile: str) -> argparse.ArgumentParser:
    if profile not in PROFILE_DESCRIPTIONS:
        raise ValueError(f"unsupported structural profile: {profile}")

    parser = argparse.ArgumentParser(
        description=PROFILE_DESCRIPTIONS[profile],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    default_output = "payloads/baseline.jsonl" if profile == "baseline" else "payloads/parser-stress.jsonl"
    parser.add_argument("--stress-profile", choices=[profile], default=profile)
    parser.add_argument("--output", default=default_output)
    parser.add_argument("--payload", default="normal-client-value")
    parser.add_argument("--path", default="/endpoint")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sizes", type=int, nargs="+")
    parser.add_argument(
        "--formats",
        nargs="+",
        choices=list(payload_gen.BASE_STRUCTURES),
        default=list(payload_gen.BASE_STRUCTURES) if profile == "baseline" else ["json", "form", "xml", "multipart", "text"],
    )
    parser.add_argument("--charsets", nargs="+", default=["utf-8", "utf-16le", "utf-16be"] if profile == "baseline" else ["utf-8"])
    parser.add_argument(
        "--compressions",
        nargs="+",
        choices=["none", "gzip", "deflate", "raw-deflate", "br"],
        default=["none", "gzip", "deflate"] if profile == "baseline" else ["none"],
        help="Ordinary single-layer compression. Specialized decompression stress belongs to decompression-stress.",
    )
    parser.add_argument("--bom", nargs="+", type=parse_bool, default=[False, True] if profile == "baseline" else [False])
    parser.add_argument("--value-encoding-profile", choices=["plain", "recommended"], default="recommended" if profile == "baseline" else "plain")
    parser.add_argument("--value-encodings", nargs="+", choices=payload_gen.ALL_VALUE_ENCODINGS)
    parser.add_argument("--depth", type=int, default=64)
    parser.add_argument("--width", type=int, default=256)
    parser.add_argument("--fields", type=int, default=512)

    if profile == "baseline":
        parser.add_argument(
            "--filler-kinds",
            nargs="+",
            choices=["repeated", "random-ascii", "unicode", "numeric"],
            default=["repeated", "random-ascii", "unicode"],
        )
    else:
        parser.add_argument("--size-profile", choices=["default", "boundaries"], default="boundaries")
        parser.add_argument(
            "--charset-modes",
            nargs="+",
            choices=["valid", "mismatch", "invalid-tail", "truncated-code-unit"],
            default=["valid"],
        )
        parser.add_argument(
            "--filler-kinds",
            nargs="+",
            choices=["repeated", "random-ascii", "unicode", "numeric", "escape-json", "escape-xml", "escape-form"],
            default=["repeated", "escape-json", "escape-xml", "escape-form"],
        )
        parser.add_argument("--field-name-lengths", type=int, nargs="+", default=[16, 256, 1024, 8192])
        parser.add_argument("--multipart-boundary-lengths", type=int, nargs="+", default=[70, 256, 1024, 8192])
        parser.add_argument("--include-corrupt-compression", action="store_true")

    return parser


def parse_args(profile: str) -> argparse.Namespace:
    parser = build_parser(profile)
    args = parser.parse_args()

    if profile == "baseline":
        args.size_profile = "default"
        args.charset_modes = ["valid"]
        args.field_name_lengths = [16]
        args.multipart_boundary_lengths = [70]
        args.include_corrupt_compression = False
        if args.sizes is None:
            args.sizes = [0, 100, 1000, 10000]
    else:
        if args.sizes is None:
            args.sizes = payload_gen.BOUNDARY_SIZES if args.size_profile == "boundaries" else [1, 1024, 8192, 65536]

    numeric_groups = {
        "sizes": args.sizes,
        "field-name-lengths": args.field_name_lengths,
        "multipart-boundary-lengths": args.multipart_boundary_lengths,
    }
    for option, values in numeric_groups.items():
        if any(value < 0 for value in values):
            parser.error(f"--{option} values must be non-negative")
    return args


def iter_cases(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    profile = args.stress_profile
    original = payload_gen.structures_for

    def selected_structures(fmt: str, _args: argparse.Namespace) -> list[str]:
        return structures_for_profile(profile, fmt)

    payload_gen.structures_for = selected_structures
    try:
        for case in payload_gen.iter_cases(args):
            metadata = case.setdefault("metadata", {})
            metadata["stress_profile"] = profile
            metadata["profile_scope"] = "representative-baseline" if profile == "baseline" else "parser-allocator-stress"
            yield case
    finally:
        payload_gen.structures_for = original


def parse_current_profile() -> argparse.Namespace:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--stress-profile", choices=list(PROFILE_DESCRIPTIONS), default="baseline")
    namespace, _ = pre_parser.parse_known_args(sys.argv[1:])
    return parse_args(namespace.stress_profile)
