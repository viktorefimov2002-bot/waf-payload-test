#!/usr/bin/env python3
"""Strict YAML configuration loading for payload generation profiles."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

PROFILES = {"baseline", "parser-stress", "decompression-stress"}
COMMON_ROOT = {"version", "profile", "output", "metadata", "safety", "generation"}
COMMON_OUTPUT = {"file", "request_path", "overwrite"}
COMMON_METADATA = {"suite_name", "description", "tags"}
COMMON_SAFETY = {"max_cases", "max_wire_body_size", "max_decompressed_size"}

BASELINE_KEYS = {
    "formats", "sizes", "charsets", "bom", "filler_kinds", "value_encoding_profile",
    "value_encodings", "compressions", "structures", "payload", "seed",
}
PARSER_KEYS = {
    "formats", "sizes", "charsets", "filler_kinds", "value_encoding_profile",
    "value_encodings", "compressions", "structures", "invalid_compression", "payload", "seed",
}
DECOMP_KEYS = {
    "formats", "algorithms", "variants", "decompressed_sizes", "gzip_members",
    "sync_flush", "nesting", "content",
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class LoadedConfig:
    path: Path
    profile: str
    output_file: Path
    request_path: str
    overwrite: bool
    metadata: dict[str, Any]
    safety: dict[str, int]
    args: argparse.Namespace
    estimated_cases: int


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{path} must be a mapping")
    return value


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{path} must be a non-empty list")
    return value


def _forbid_extra(mapping: dict[str, Any], allowed: set[str], path: str) -> None:
    extra = sorted(set(mapping) - allowed)
    if extra:
        raise ConfigError(f"unsupported option(s) for {path}: {', '.join(extra)}")


def _positive_int(value: Any, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConfigError(f"{path} must be a positive integer")
    return value


def _non_negative_ints(value: Any, path: str) -> list[int]:
    values = _list(value, path)
    if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in values):
        raise ConfigError(f"{path} must contain non-negative integers")
    return values


def _base(data: dict[str, Any], config_path: Path) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    _forbid_extra(data, COMMON_ROOT, "root")
    if data.get("version") != 1:
        raise ConfigError("version must be 1")
    profile = data.get("profile")
    if profile not in PROFILES:
        raise ConfigError(f"profile must be one of: {', '.join(sorted(PROFILES))}")
    output = _mapping(data.get("output", {}), "output")
    metadata = _mapping(data.get("metadata", {}), "metadata")
    safety = _mapping(data.get("safety", {}), "safety")
    generation = _mapping(data.get("generation", {}), "generation")
    _forbid_extra(output, COMMON_OUTPUT, "output")
    _forbid_extra(metadata, COMMON_METADATA, "metadata")
    _forbid_extra(safety, COMMON_SAFETY, "safety")
    return profile, output, metadata, safety, generation


def _structural_namespace(profile: str, generation: dict[str, Any], request_path: str, output_file: Path) -> tuple[argparse.Namespace, int]:
    allowed = BASELINE_KEYS if profile == "baseline" else PARSER_KEYS
    _forbid_extra(generation, allowed, f'generation for profile "{profile}"')
    structures = _mapping(generation.get("structures", {}), "generation.structures")
    structure_allowed = {"depth", "width", "fields"}
    if profile == "parser-stress":
        structure_allowed |= {"field_name_lengths", "multipart_boundary_lengths"}
    _forbid_extra(structures, structure_allowed, "generation.structures")

    formats = _list(generation.get("formats"), "generation.formats")
    sizes_raw = generation.get("sizes")
    if isinstance(sizes_raw, dict):
        _forbid_extra(sizes_raw, {"mode", "values"}, "generation.sizes")
        sizes = _non_negative_ints(sizes_raw.get("values"), "generation.sizes.values")
    else:
        sizes = _non_negative_ints(sizes_raw, "generation.sizes")

    charset_cfg = generation.get("charsets")
    if profile == "parser-stress":
        charset_cfg = _mapping(charset_cfg, "generation.charsets")
        _forbid_extra(charset_cfg, {"declared", "modes", "bom"}, "generation.charsets")
        charsets = _list(charset_cfg.get("declared"), "generation.charsets.declared")
        charset_modes = _list(charset_cfg.get("modes"), "generation.charsets.modes")
        bom = _list(charset_cfg.get("bom"), "generation.charsets.bom")
    else:
        charsets = _list(charset_cfg, "generation.charsets")
        charset_modes = ["valid"]
        bom = _list(generation.get("bom"), "generation.bom")

    invalid_cfg = _mapping(generation.get("invalid_compression", {}), "generation.invalid_compression") if profile == "parser-stress" else {}
    if invalid_cfg:
        _forbid_extra(invalid_cfg, {"enabled", "modes"}, "generation.invalid_compression")
    include_corrupt = bool(invalid_cfg.get("enabled", False))

    args = argparse.Namespace(
        stress_profile="phase1" if profile == "parser-stress" else "baseline",
        output=str(output_file), path=request_path,
        payload=str(generation.get("payload", "normal-client-value")), seed=int(generation.get("seed", 42)),
        formats=formats, sizes=sizes, size_profile="default", charsets=charsets,
        charset_modes=charset_modes, bom=bom,
        filler_kinds=_list(generation.get("filler_kinds"), "generation.filler_kinds"),
        value_encoding_profile=str(generation.get("value_encoding_profile", "plain")),
        value_encodings=generation.get("value_encodings"),
        compressions=_list(generation.get("compressions"), "generation.compressions"),
        depth=int(structures.get("depth", 64)), width=int(structures.get("width", 256)),
        fields=int(structures.get("fields", 512)),
        field_name_lengths=structures.get("field_name_lengths", [16]),
        multipart_boundary_lengths=structures.get("multipart_boundary_lengths", [70]),
        include_corrupt_compression=include_corrupt,
    )
    for name in ("depth", "width", "fields"):
        _positive_int(getattr(args, name), f"generation.structures.{name}")
    estimate = len(formats) * len(sizes) * len(charsets) * len(charset_modes) * len(bom) * len(args.filler_kinds) * len(args.compressions)
    return args, estimate


def _decompression_namespace(generation: dict[str, Any], request_path: str, output_file: Path) -> tuple[argparse.Namespace, int]:
    _forbid_extra(generation, DECOMP_KEYS, 'generation for profile "decompression-stress"')
    members = _mapping(generation.get("gzip_members", {}), "generation.gzip_members")
    flush = _mapping(generation.get("sync_flush", {}), "generation.sync_flush")
    nesting = _mapping(generation.get("nesting", {}), "generation.nesting")
    content = _mapping(generation.get("content", {}), "generation.content")
    _forbid_extra(members, {"counts"}, "generation.gzip_members")
    _forbid_extra(flush, {"chunk_sizes"}, "generation.sync_flush")
    _forbid_extra(nesting, {"depths"}, "generation.nesting")
    _forbid_extra(content, {"seed_text"}, "generation.content")
    args = argparse.Namespace(
        stress_profile="decompression-stress", output=str(output_file), path=request_path,
        formats=_list(generation.get("formats"), "generation.formats"),
        algorithms=_list(generation.get("algorithms"), "generation.algorithms"),
        variants=_list(generation.get("variants"), "generation.variants"),
        decompressed_sizes=_non_negative_ints(generation.get("decompressed_sizes"), "generation.decompressed_sizes"),
        member_counts=_non_negative_ints(members.get("counts"), "generation.gzip_members.counts"),
        flush_chunk_sizes=_non_negative_ints(flush.get("chunk_sizes"), "generation.sync_flush.chunk_sizes"),
        nested_depths=_non_negative_ints(nesting.get("depths"), "generation.nesting.depths"),
        seed_text=str(content.get("seed_text", "A")),
    )
    estimate = len(args.formats) * len(args.decompressed_sizes) * max(1, len(args.algorithms)) * max(1, len(args.variants))
    return args, estimate


def load_config(path: str | Path, output_override: str | None = None, request_path_override: str | None = None) -> LoadedConfig:
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from exc
    data = _mapping(raw, "root")
    profile, output, metadata, safety, generation = _base(data, config_path)
    output_file = Path(output_override or output.get("file", f"payloads_{profile}.jsonl"))
    request_path = str(request_path_override or output.get("request_path", f"/waf-test/{profile}"))
    overwrite = bool(output.get("overwrite", False))
    normalized_safety = {
        "max_cases": _positive_int(safety.get("max_cases", 50000), "safety.max_cases"),
        "max_wire_body_size": _positive_int(safety.get("max_wire_body_size", 128 * 1024 * 1024), "safety.max_wire_body_size"),
        "max_decompressed_size": _positive_int(safety.get("max_decompressed_size", 256 * 1024 * 1024), "safety.max_decompressed_size"),
    }
    if profile == "decompression-stress":
        args, estimate = _decompression_namespace(generation, request_path, output_file)
        if max(args.decompressed_sizes) > normalized_safety["max_decompressed_size"]:
            raise ConfigError("generation.decompressed_sizes exceeds safety.max_decompressed_size")
    else:
        args, estimate = _structural_namespace(profile, generation, request_path, output_file)
    if estimate > normalized_safety["max_cases"]:
        raise ConfigError(f"estimated case count {estimate} exceeds safety.max_cases {normalized_safety['max_cases']}")
    return LoadedConfig(config_path, profile, output_file, request_path, overwrite, metadata, normalized_safety, args, estimate)
