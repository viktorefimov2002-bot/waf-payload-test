#!/usr/bin/env python3
"""User-facing adapter for the decompression-stress profile."""
from __future__ import annotations

import argparse
from collections.abc import Iterable
from typing import Any

from . import decompression_profile

PROFILE = "decompression-stress"
LEGACY_PROFILE = "phase2"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Controlled WAF decompression stress: large expansion ratios, concatenated gzip members, "
            "frequent flushes, stored blocks and nested Content-Encoding chains."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--stress-profile", choices=[PROFILE], default=PROFILE)
    parser.add_argument("--output", default="payloads/decompression-stress.jsonl")
    parser.add_argument("--path", default="/decompression-test")
    parser.add_argument("--formats", nargs="+", choices=["json", "text"], default=["json"])
    parser.add_argument("--algorithms", nargs="+", choices=decompression_profile.ALGORITHMS, default=["gzip", "deflate", "raw-deflate"])
    parser.add_argument("--variants", nargs="+", choices=decompression_profile.VARIANTS, default=["standard", "gzip-members", "sync-flush", "nested-same"])
    parser.add_argument("--decompressed-sizes", nargs="+", type=int, default=decompression_profile.DEFAULT_DECOMPRESSED_SIZES, metavar="BYTES")
    parser.add_argument("--member-counts", nargs="+", type=int, default=[2, 8, 32])
    parser.add_argument("--flush-chunk-sizes", nargs="+", type=int, default=[64, 1024, 16384])
    parser.add_argument("--nested-depths", nargs="+", type=int, default=[2, 3])
    parser.add_argument("--max-decompressed-size", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--seed-text", default="A")
    return parser


def parse_args() -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args()
    groups = {
        "decompressed-sizes": args.decompressed_sizes,
        "member-counts": args.member_counts,
        "flush-chunk-sizes": args.flush_chunk_sizes,
        "nested-depths": args.nested_depths,
    }
    for option, values in groups.items():
        if any(value < 1 for value in values):
            parser.error(f"--{option} values must be positive")
    if args.max_decompressed_size < 1:
        parser.error("--max-decompressed-size must be positive")
    if max(args.decompressed_sizes) > args.max_decompressed_size:
        parser.error("requested decompressed size exceeds --max-decompressed-size")
    if not args.seed_text:
        parser.error("--seed-text must not be empty")
    args.stress_profile = LEGACY_PROFILE
    return args


def iter_cases(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    args.stress_profile = LEGACY_PROFILE
    for case in decompression_profile.iter_cases(args):
        metadata = case.setdefault("metadata", {})
        metadata["stress_profile"] = PROFILE
        metadata["profile_scope"] = "decompression-stream-stress"
        yield case
