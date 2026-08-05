import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


MODULE_PATH = Path("tools/case_to_curl.py")
SPEC = importlib.util.spec_from_file_location("case_to_curl", MODULE_PATH)
assert SPEC and SPEC.loader
case_to_curl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(case_to_curl)


def make_case(body: bytes = b'{"hello":"world"}') -> dict:
    return {
        "id": "case-test-json-gzip",
        "method": "POST",
        "path": "/waf-test/debug?x=1",
        "headers": {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Encoding": "gzip",
            "Content-Length": "999999",
            "X-Custom": "value with spaces",
        },
        "body_base64": base64.b64encode(body).decode("ascii"),
        "wire_body_size": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "metadata": {"format": "json"},
    }


def test_find_case_in_jsonl(tmp_path: Path):
    path = tmp_path / "cases.jsonl"
    expected = make_case()
    path.write_text(json.dumps(expected) + "\n", encoding="utf-8")
    assert case_to_curl.find_case(path, expected["id"]) == expected


def test_find_case_in_legacy_json_array(tmp_path: Path):
    path = tmp_path / "cases.json"
    expected = make_case()
    path.write_text(json.dumps([expected]), encoding="utf-8")
    assert case_to_curl.find_case(path, expected["id"]) == expected


def test_decode_wire_body_validates_size_and_sha256():
    expected = b"exact-wire-body"
    assert case_to_curl.decode_wire_body(make_case(expected)) == expected

    invalid = make_case(expected)
    invalid["sha256"] = "0" * 64
    with pytest.raises(case_to_curl.CaseCurlError, match="SHA-256 mismatch"):
        case_to_curl.decode_wire_body(invalid)


def test_build_curl_preserves_encoding_and_uses_body_file(tmp_path: Path):
    case = make_case()
    body_file = tmp_path / "wire body.bin"
    args = case_to_curl.build_curl_args(
        case,
        target="https://example.test/base",
        body_file=body_file,
        insecure=True,
        include_debug_headers=True,
        timeout=12.5,
        output_headers=True,
    )

    joined = "\n".join(args)
    assert "Content-Encoding: gzip" in joined
    assert "Content-Type: application/json; charset=utf-8" in joined
    assert "Content-Length" not in joined
    assert "X-WAF-Test-Case-ID: case-test-json-gzip" in joined
    assert f"@{body_file}" in args
    assert args[-1] == "https://example.test/waf-test/debug?x=1"
    assert "--insecure" in args
    assert "--include" in args


def test_shell_command_quotes_paths_and_header_values(tmp_path: Path):
    case = make_case()
    args = case_to_curl.build_curl_args(
        case,
        target="https://example.test",
        body_file=tmp_path / "body with spaces.bin",
        insecure=False,
        include_debug_headers=False,
        timeout=None,
        output_headers=False,
    )
    command = case_to_curl.shell_command(args)
    assert "'X-Custom: value with spaces'" in command
    assert "'@" in command
