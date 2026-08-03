from __future__ import annotations

import argparse

from modules import decompression_stress_profile
from modules import parser_stress_profile
from modules import structural_profile
import payload_gen_jsonl


def option_names(parser: argparse.ArgumentParser) -> set[str]:
    return {
        option
        for action in parser._actions
        for option in action.option_strings
    }


def test_baseline_and_parser_stress_structures_are_disjoint():
    for fmt in ("json", "form", "xml", "multipart", "text", "octet-stream"):
        baseline = set(structural_profile.structures_for_profile("baseline", fmt))
        parser_stress = set(structural_profile.structures_for_profile("phase1", fmt))
        assert baseline.isdisjoint(parser_stress), (fmt, baseline & parser_stress)


def test_profile_specific_cli_options_do_not_leak():
    baseline_options = option_names(structural_profile.build_parser("baseline"))
    parser_options = option_names(parser_stress_profile.build_parser())
    decompression_options = option_names(decompression_stress_profile.build_parser())

    assert "--field-name-lengths" not in baseline_options
    assert "--charset-modes" not in baseline_options
    assert "--member-counts" not in baseline_options

    assert "--field-name-lengths" in parser_options
    assert "--charset-modes" in parser_options
    assert "--member-counts" not in parser_options

    assert "--member-counts" in decompression_options
    assert "--decompressed-sizes" in decompression_options
    assert "--depth" not in decompression_options
    assert "--field-name-lengths" not in decompression_options


def test_router_exposes_readable_profiles_and_legacy_aliases():
    assert set(payload_gen_jsonl.PROFILE_DESCRIPTIONS) == {
        "baseline",
        "parser-stress",
        "decompression-stress",
    }
    assert payload_gen_jsonl.canonical_profile("phase1") == "parser-stress"
    assert payload_gen_jsonl.canonical_profile("phase2") == "decompression-stress"


def test_decompression_cases_have_canonical_profile_name():
    args = argparse.Namespace(
        stress_profile="phase2",
        formats=["json"],
        algorithms=["gzip"],
        variants=["standard"],
        decompressed_sizes=[4096],
        member_counts=[2],
        flush_chunk_sizes=[64],
        nested_depths=[2],
        seed_text="A",
        path="/test",
    )
    case = next(iter(decompression_stress_profile.iter_cases(args)))
    assert case["metadata"]["test_dimension"] == "decompression"
    assert case["metadata"]["stress_profile"] == "decompression-stress"
