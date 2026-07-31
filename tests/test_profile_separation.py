from __future__ import annotations

import argparse
import sys

import pytest

import _decompression_profile
import _structural_profile
import payload_gen_jsonl


def option_names(parser: argparse.ArgumentParser) -> set[str]:
    return {
        option
        for action in parser._actions
        for option in action.option_strings
    }


def test_baseline_and_phase1_structures_are_disjoint():
    for fmt in ("json", "form", "xml", "multipart", "text", "octet-stream"):
        baseline = set(_structural_profile.structures_for_profile("baseline", fmt))
        phase1 = set(_structural_profile.structures_for_profile("phase1", fmt))
        assert baseline.isdisjoint(phase1), (fmt, baseline & phase1)


def test_baseline_and_phase1_cli_options_do_not_leak():
    baseline_options = option_names(_structural_profile.build_parser("baseline"))
    phase1_options = option_names(_structural_profile.build_parser("phase1"))

    assert "--field-name-lengths" not in baseline_options
    assert "--charset-modes" not in baseline_options
    assert "--member-counts" not in baseline_options

    assert "--field-name-lengths" in phase1_options
    assert "--charset-modes" in phase1_options
    assert "--member-counts" not in phase1_options


def test_phase2_help_exposes_only_decompression_options(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["payload_gen_jsonl.py", "--stress-profile", "phase2", "--help"])
    with pytest.raises(SystemExit) as exc:
        _decompression_profile.parse_args()
    assert exc.value.code == 0
    help_text = capsys.readouterr().out

    assert "--member-counts" in help_text
    assert "--decompressed-sizes" in help_text
    assert "--nested-depths" in help_text
    assert "--depth" not in help_text
    assert "--field-name-lengths" not in help_text
    assert "--charset-modes" not in help_text


def test_router_exposes_three_distinct_profiles():
    assert set(payload_gen_jsonl.PROFILE_DESCRIPTIONS) == {"baseline", "phase1", "phase2"}


def test_phase2_cases_have_decompression_dimension():
    args = argparse.Namespace(
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
    case = next(iter(_decompression_profile.iter_cases(args)))
    assert case["metadata"]["test_dimension"] == "decompression"
    assert case["metadata"]["compression_variant"] == "standard"
