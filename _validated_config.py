#!/usr/bin/env python3
"""Final YAML validation with exact profile-aware case estimation."""
from __future__ import annotations

from dataclasses import replace
from typing import Any

import payload_gen
from _config_loader import ConfigError, LoadedConfig, load_config as load_base_config


def _encoding_count(fmt: str, structure: str, args: Any) -> int:
    if structure == "invalid-percent":
        return 1
    if args.value_encodings:
        return len([item for item in args.value_encodings if item in payload_gen.RECOMMENDED_VALUE_ENCODINGS[fmt]])
    if args.value_encoding_profile == "recommended":
        return len(payload_gen.RECOMMENDED_VALUE_ENCODINGS[fmt])
    return 1


def _structure_multiplier(profile: str, fmt: str, structure: str, args: Any) -> int:
    if profile != "parser-stress":
        return 1
    if structure in {
        "long-field-name", "many-long-field-names", "long-element-name",
        "long-attribute-name", "long-name", "long-filename",
    }:
        return len(args.field_name_lengths)
    if structure == "long-boundary":
        return len(args.multipart_boundary_lengths)
    return 1


def estimate_structural(profile: str, args: Any) -> int:
    structures_by_format = payload_gen.BASE_STRUCTURES if profile == "baseline" else payload_gen.PHASE1_STRUCTURES
    compression_variants = sum(
        1 + (3 if args.include_corrupt_compression and compression != "none" else 0)
        for compression in args.compressions
    )
    total = 0
    for fmt in args.formats:
        charset_count = len(args.charsets)
        charset_mode_count = len(args.charset_modes)
        if fmt == "octet-stream":
            charset_count = int("utf-8" in args.charsets)
            charset_mode_count = int("valid" in args.charset_modes)
        structure_units = sum(
            _structure_multiplier(profile, fmt, structure, args)
            * _encoding_count(fmt, structure, args)
            for structure in structures_by_format[fmt]
        )
        total += (
            structure_units
            * charset_count
            * charset_mode_count
            * len(args.bom)
            * len(args.filler_kinds)
            * len(args.sizes)
            * compression_variants
        )
    return total


def estimate_decompression(args: Any) -> int:
    per_size = 0
    algorithms = [algorithm for algorithm in args.algorithms if algorithm != "br" or payload_gen.brotli is not None]
    for algorithm in algorithms:
        if "standard" in args.variants:
            per_size += 1
        if "stored-blocks" in args.variants and algorithm in {"gzip", "deflate", "raw-deflate"}:
            per_size += 1
        if "sync-flush" in args.variants and algorithm in {"gzip", "deflate", "raw-deflate"}:
            per_size += len(args.flush_chunk_sizes)
        if "nested-same" in args.variants:
            per_size += len(args.nested_depths)
    if "gzip-members" in args.variants and "gzip" in algorithms:
        per_size += len(args.member_counts)
    if "nested-mixed" in args.variants:
        available = set(algorithms)
        chains = [("gzip", "deflate"), ("deflate", "gzip"), ("gzip", "raw-deflate"), ("gzip", "br"), ("br", "gzip")]
        per_size += sum(all(item in available for item in chain) for chain in chains)
    return len(args.formats) * len(args.decompressed_sizes) * per_size


def load_config(path: str, output_override: str | None = None, request_path_override: str | None = None) -> LoadedConfig:
    config = load_base_config(path, output_override, request_path_override)
    estimate = (
        estimate_decompression(config.args)
        if config.profile == "decompression-stress"
        else estimate_structural(config.profile, config.args)
    )
    if estimate > config.safety["max_cases"]:
        raise ConfigError(f"estimated case count {estimate} exceeds safety.max_cases {config.safety['max_cases']}")
    return replace(config, estimated_cases=estimate)
