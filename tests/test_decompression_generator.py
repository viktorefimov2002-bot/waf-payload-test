from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import zlib

import decompression_gen


def args(**overrides):
    values = {
        "formats": ["json"],
        "algorithms": ["gzip", "deflate", "raw-deflate"],
        "variants": ["standard", "gzip-members", "sync-flush", "stored-blocks", "nested-same", "nested-mixed"],
        "decompressed_sizes": [4096],
        "member_counts": [4],
        "flush_chunk_sizes": [64],
        "nested_depths": [2],
        "seed_text": "A",
        "path": "/test",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def decode_once(data: bytes, encoding: str) -> bytes:
    if encoding == "gzip":
        return gzip.decompress(data)
    if encoding == "deflate":
        try:
            return zlib.decompress(data)
        except zlib.error:
            return zlib.decompress(data, wbits=-zlib.MAX_WBITS)
    raise AssertionError(f"unsupported test encoding: {encoding}")


def fully_decode(case: dict) -> bytes:
    data = base64.b64decode(case["body_base64"])
    for encoding in reversed(case["metadata"]["content_encoding_chain"]):
        data = decode_once(data, encoding)
    return data


def test_every_generated_case_has_exact_sha256():
    for case in decompression_gen.iter_cases(args()):
        wire = base64.b64decode(case["body_base64"])
        assert hashlib.sha256(wire).hexdigest() == case["sha256"]
        assert len(wire) == case["wire_body_size"]


def test_standard_and_nested_cases_restore_original_size():
    for case in decompression_gen.iter_cases(args()):
        if case["metadata"]["compression_variant"] == "gzip-members":
            continue
        decoded = fully_decode(case)
        assert len(decoded) == case["metadata"]["decompressed_size"]
        assert decoded.startswith(b'{"data":"')


def test_concatenated_gzip_members_restore_original_size():
    cases = list(decompression_gen.iter_cases(args(algorithms=["gzip"], variants=["gzip-members"])))
    assert cases
    case = cases[0]
    wire = base64.b64decode(case["body_base64"])
    decoded = gzip.decompress(wire)
    assert len(decoded) == case["metadata"]["decompressed_size"]
    assert case["metadata"]["gzip_member_count"] == 4


def test_sync_flush_metadata_is_recorded():
    cases = list(decompression_gen.iter_cases(args(algorithms=["deflate"], variants=["sync-flush"], flush_chunk_sizes=[32])))
    assert cases[0]["metadata"]["flush_chunk_size"] == 32


def test_nested_header_matches_chain_order():
    cases = list(decompression_gen.iter_cases(args(algorithms=["gzip"], variants=["nested-same"], nested_depths=[3])))
    case = cases[0]
    assert case["headers"]["Content-Encoding"] == "gzip, gzip, gzip"
    assert case["metadata"]["compression_layers"] == 3
