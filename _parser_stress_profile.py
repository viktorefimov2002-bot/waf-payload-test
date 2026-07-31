#!/usr/bin/env python3
"""User-facing adapter for the parser-stress profile."""
from __future__ import annotations

import argparse
from collections.abc import Iterable
from typing import Any

import _structural_profile

PROFILE = "parser-stress"
LEGACY_PROFILE = "phase1"


def build_parser() -> argparse.ArgumentParser:
    parser = _structural_profile.build_parser(LEGACY_PROFILE)
    parser.description = (
        "Parser, allocator and normalization stress: boundary sizes, deep-wide trees, "
        "long names, escape-heavy values, charset faults and multipart edge cases."
    )
    for action in parser._actions:
        if "--stress-profile" in action.option_strings:
            action.choices = [PROFILE]
            action.default = PROFILE
            break
    return parser


def parse_args() -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args()
    args.stress_profile = LEGACY_PROFILE
    if args.sizes is None:
        args.sizes = (
            _structural_profile.payload_gen.BOUNDARY_SIZES
            if args.size_profile == "boundaries"
            else [1, 1024, 8192, 65536]
        )
    return args


def iter_cases(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    args.stress_profile = LEGACY_PROFILE
    for case in _structural_profile.iter_cases(args):
        metadata = case.setdefault("metadata", {})
        metadata["stress_profile"] = PROFILE
        metadata["profile_scope"] = "parser-allocator-normalization-stress"
        yield case
