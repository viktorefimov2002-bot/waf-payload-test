from __future__ import annotations

import argparse
import base64
import hashlib
import json

from modules import structural_profile
import payload_gen


def args(**overrides):
    values = {
        "formats": ["json"],
        "stress_profile": "phase1",
        "field_name_lengths": [16],
        "multipart_boundary_lengths": [70],
        "charsets": ["utf-8"],
        "charset_modes": ["valid"],
        "bom": [False],
        "filler_kinds": ["repeated"],
        "sizes": [1],
        "payload": "",
        "seed": 42,
        "value_encodings": ["plain"],
        "value_encoding_profile": "plain",
        "depth": 3,
        "width": 4,
        "fields": 5,
        "compressions": ["none"],
        "include_corrupt_compression": False,
        "path": "/test",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_phase1_contains_only_phase1_json_structures():
    structures = {case["metadata"]["structure"] for case in structural_profile.iter_cases(args())}
    assert structures == set(payload_gen.PHASE1_STRUCTURES["json"])
    assert structures.isdisjoint(payload_gen.BASE_STRUCTURES["json"])


def test_long_field_name_length_is_preserved():
    cases = list(structural_profile.iter_cases(args(field_name_lengths=[256])))
    case = next(item for item in cases if item["metadata"]["structure"] == "long-field-name")
    body = base64.b64decode(case["body_base64"])
    decoded = json.loads(body)
    assert case["metadata"]["field_name_length"] == 256
    assert len(next(iter(decoded))) == 256


def test_charset_mismatch_is_marked_and_byte_exact():
    cases = list(structural_profile.iter_cases(args(charset_modes=["mismatch"])))
    case = cases[0]
    body = base64.b64decode(case["body_base64"])
    assert case["metadata"]["validity"] == "invalid-charset"
    assert case["metadata"]["actual_charset"] != case["metadata"]["charset"]
    assert hashlib.sha256(body).hexdigest() == case["sha256"]


def test_boundary_size_profile_contains_plus_minus_one_values():
    assert 8191 in payload_gen.BOUNDARY_SIZES
    assert 8192 in payload_gen.BOUNDARY_SIZES
    assert 8193 in payload_gen.BOUNDARY_SIZES
    assert 65535 in payload_gen.BOUNDARY_SIZES
    assert 65536 in payload_gen.BOUNDARY_SIZES
    assert 65537 in payload_gen.BOUNDARY_SIZES
