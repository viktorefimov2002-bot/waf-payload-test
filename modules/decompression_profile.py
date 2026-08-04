#!/usr/bin/env python3
"""Internal implementation for decompression stress payloads."""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import random
import zlib
from typing import Any, Iterable

try:
    import brotli  # type: ignore
except ImportError:  # pragma: no cover
    brotli = None

DEFAULT_DECOMPRESSED_SIZES = [1024 * 1024, 8 * 1024 * 1024, 64 * 1024 * 1024]
ALGORITHMS = ["gzip", "deflate", "raw-deflate", "br"]
VARIANTS = ["standard", "gzip-members", "sync-flush", "stored-blocks", "nested-same", "nested-mixed"]
CONTENT_PROFILES = ["highly-compressible", "medium-compressible", "incompressible"]
SAFE_RANDOM_ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate controlled compressed request bodies for WAF decompression stress testing"
    )
    parser.add_argument("--stress-profile", choices=["phase2"], default="phase2")
    parser.add_argument("--output", default="payloads/decompression-stress.jsonl", help="Output JSONL manifest")
    parser.add_argument("--path", default="/decompression-test", help="Request path")
    parser.add_argument("--formats", nargs="+", choices=["json", "text"], default=["json"])
    parser.add_argument("--algorithms", nargs="+", choices=ALGORITHMS, default=["gzip", "deflate", "raw-deflate"])
    parser.add_argument("--variants", nargs="+", choices=VARIANTS, default=["standard", "gzip-members", "sync-flush", "nested-same"])
    parser.add_argument("--decompressed-sizes", nargs="+", type=int, default=DEFAULT_DECOMPRESSED_SIZES, metavar="BYTES")
    parser.add_argument("--member-counts", nargs="+", type=int, default=[2, 8, 32])
    parser.add_argument("--flush-chunk-sizes", nargs="+", type=int, default=[64, 1024, 16384])
    parser.add_argument("--nested-depths", nargs="+", type=int, default=[2, 3])
    parser.add_argument("--max-decompressed-size", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--content-profile", choices=CONTENT_PROFILES, default="highly-compressible")
    parser.add_argument("--seed-text", default="A", help="Repeated text pattern for compressible profiles")
    parser.add_argument("--random-seed", type=int, default=42, help="Deterministic seed for mixed/random profiles")
    args = parser.parse_args()

    numeric_groups = {
        "decompressed-sizes": args.decompressed_sizes,
        "member-counts": args.member_counts,
        "flush-chunk-sizes": args.flush_chunk_sizes,
        "nested-depths": args.nested_depths,
    }
    for option, values in numeric_groups.items():
        if any(value < 1 for value in values):
            parser.error(f"--{option} values must be positive")
    if args.max_decompressed_size < 1:
        parser.error("--max-decompressed-size must be positive")
    if args.random_seed < 1:
        parser.error("--random-seed must be positive")
    too_large = [size for size in args.decompressed_sizes if size > args.max_decompressed_size]
    if too_large:
        parser.error(
            f"requested decompressed size exceeds --max-decompressed-size: {max(too_large)} > {args.max_decompressed_size}"
        )
    if not args.seed_text:
        parser.error("--seed-text must not be empty")
    return args


def repeat_bytes(pattern: bytes, size: int) -> bytes:
    return (pattern * (size // len(pattern) + 1))[:size]


def deterministic_ascii(size: int, seed: int) -> bytes:
    """Return reproducible JSON-safe pseudo-random ASCII without a huge temporary list."""
    rng = random.Random(seed)
    output = bytearray()
    chunk_size = 1024 * 1024
    alphabet = SAFE_RANDOM_ALPHABET
    while len(output) < size:
        take = min(chunk_size, size - len(output))
        raw = rng.randbytes(take)
        output.extend(alphabet[value % len(alphabet)] for value in raw)
    return bytes(output)


def build_profile_payload(profile: str, size: int, seed_text: str, random_seed: int) -> bytes:
    repeated = repeat_bytes(seed_text.encode("utf-8"), size)
    if profile == "highly-compressible":
        return repeated
    random_data = deterministic_ascii(size, random_seed + size)
    if profile == "incompressible":
        return random_data
    if profile == "medium-compressible":
        # Deterministic 4 KiB blocks: three repeated blocks followed by one random block.
        block_size = 4096
        output = bytearray()
        for offset in range(0, size, block_size):
            end = min(size, offset + block_size)
            source = random_data if (offset // block_size) % 4 == 3 else repeated
            output.extend(source[offset:end])
        return bytes(output)
    raise ValueError(f"unsupported content profile: {profile}")


def build_serialized_body(fmt: str, target_size: int, content_profile: str, seed_text: str, random_seed: int) -> bytes:
    if fmt == "text":
        return build_profile_payload(content_profile, target_size, seed_text, random_seed)
    prefix = b'{"data":"'
    suffix = b'"}'
    payload_size = max(0, target_size - len(prefix) - len(suffix))
    payload = build_profile_payload(content_profile, payload_size, seed_text, random_seed)
    body = prefix + payload + suffix
    if len(body) < target_size:
        body += b" " * (target_size - len(body))
    return body[:target_size]


def zlib_stream(data: bytes, *, wbits: int, level: int = 6, chunk_size: int | None = None) -> bytes:
    compressor = zlib.compressobj(level=level, wbits=wbits)
    if chunk_size is None:
        return compressor.compress(data) + compressor.flush()
    output = bytearray()
    for offset in range(0, len(data), chunk_size):
        output.extend(compressor.compress(data[offset : offset + chunk_size]))
        output.extend(compressor.flush(zlib.Z_SYNC_FLUSH))
    output.extend(compressor.flush(zlib.Z_FINISH))
    return bytes(output)


def compress_once(data: bytes, algorithm: str, *, level: int = 6, chunk_size: int | None = None) -> bytes:
    if algorithm == "gzip":
        if chunk_size is None and level != 0:
            return gzip.compress(data, compresslevel=level, mtime=0)
        return zlib_stream(data, wbits=16 + zlib.MAX_WBITS, level=level, chunk_size=chunk_size)
    if algorithm == "deflate":
        return zlib_stream(data, wbits=zlib.MAX_WBITS, level=level, chunk_size=chunk_size)
    if algorithm == "raw-deflate":
        return zlib_stream(data, wbits=-zlib.MAX_WBITS, level=level, chunk_size=chunk_size)
    if algorithm == "br":
        if brotli is None:
            raise RuntimeError("brotli module is not installed")
        if chunk_size is not None or level == 0:
            raise ValueError("Brotli does not support sync-flush/stored-block variants in this generator")
        return brotli.compress(data)
    raise ValueError(f"unsupported algorithm: {algorithm}")


def content_encoding_name(algorithm: str) -> str:
    return "deflate" if algorithm == "raw-deflate" else algorithm


def apply_chain(data: bytes, chain: list[str]) -> bytes:
    result = data
    for algorithm in chain:
        result = compress_once(result, algorithm)
    return result


def split_evenly(data: bytes, count: int) -> list[bytes]:
    count = min(count, max(1, len(data)))
    base, extra = divmod(len(data), count)
    parts: list[bytes] = []
    offset = 0
    for index in range(count):
        length = base + (1 if index < extra else 0)
        parts.append(data[offset : offset + length])
        offset += length
    return parts


def variants_for(data: bytes, algorithms: list[str], variants: list[str], args: argparse.Namespace) -> Iterable[tuple[str, bytes, list[str], dict[str, Any]]]:
    for algorithm in algorithms:
        if algorithm == "br" and brotli is None:
            continue
        if "standard" in variants:
            yield "standard", compress_once(data, algorithm), [algorithm], {}
        if "stored-blocks" in variants and algorithm in {"gzip", "deflate", "raw-deflate"}:
            yield "stored-blocks", compress_once(data, algorithm, level=0), [algorithm], {"compression_level": 0}
        if "sync-flush" in variants and algorithm in {"gzip", "deflate", "raw-deflate"}:
            for chunk_size in args.flush_chunk_sizes:
                yield "sync-flush", compress_once(data, algorithm, chunk_size=chunk_size), [algorithm], {"flush_chunk_size": chunk_size}
        if "nested-same" in variants:
            for depth in args.nested_depths:
                chain = [algorithm] * depth
                yield "nested-same", apply_chain(data, chain), chain, {"nested_depth": depth}

    if "gzip-members" in variants and "gzip" in algorithms:
        for member_count in args.member_counts:
            members = [gzip.compress(part, compresslevel=6, mtime=0) for part in split_evenly(data, member_count)]
            yield "gzip-members", b"".join(members), ["gzip"], {"gzip_member_count": len(members)}

    if "nested-mixed" in variants:
        available = [algorithm for algorithm in algorithms if algorithm != "br" or brotli is not None]
        chains = [["gzip", "deflate"], ["deflate", "gzip"]]
        if "raw-deflate" in available:
            chains.append(["gzip", "raw-deflate"])
        if "br" in available:
            chains.extend([["gzip", "br"], ["br", "gzip"]])
        for chain in chains:
            if all(item in available for item in chain):
                yield "nested-mixed", apply_chain(data, chain), chain, {"nested_depth": len(chain)}


def make_case(case_number: int, fmt: str, serialized: bytes, variant: str, wire: bytes, chain: list[str], details: dict[str, Any], path: str, content_profile: str, random_seed: int) -> dict[str, Any]:
    encoding_header = ", ".join(content_encoding_name(item) for item in chain)
    case_id = f"decomp-{case_number:06d}-{fmt}-{content_profile}-{variant}-{'-'.join(chain)}-{len(serialized)}"
    ratio = len(serialized) / max(1, len(wire))
    return {
        "id": case_id,
        "method": "POST",
        "path": path,
        "headers": {
            "Content-Type": "application/json; charset=utf-8" if fmt == "json" else "text/plain; charset=utf-8",
            "Content-Encoding": encoding_header,
            "X-WAF-Test-Case-ID": case_id,
        },
        "body_base64": base64.b64encode(wire).decode("ascii"),
        "sha256": hashlib.sha256(wire).hexdigest(),
        "logical_size": len(serialized),
        "serialized_size": len(serialized),
        "wire_body_size": len(wire),
        "expansion_ratio": round(ratio, 4),
        "metadata": {
            "test_dimension": "decompression",
            "stress_profile": "phase2",
            "format": fmt,
            "structure": "single",
            "validity": "valid",
            "content_profile": content_profile,
            "content_random_seed": random_seed,
            "compression": content_encoding_name(chain[-1]),
            "compression_variant": variant,
            "content_encoding_chain": [content_encoding_name(item) for item in chain],
            "compression_layers": len(chain),
            "decompressed_size": len(serialized),
            "compressed_size": len(wire),
            "expansion_ratio": round(ratio, 4),
            **details,
        },
    }


def iter_cases(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    case_number = 0
    if "br" in args.algorithms and brotli is None:
        print("Warning: brotli is unavailable; br cases are skipped.")
    for fmt in args.formats:
        for target_size in args.decompressed_sizes:
            serialized = build_serialized_body(fmt, target_size, args.content_profile, args.seed_text, args.random_seed)
            for variant, wire, chain, details in variants_for(serialized, args.algorithms, args.variants, args):
                case_number += 1
                yield make_case(
                    case_number, fmt, serialized, variant, wire, chain, details,
                    args.path, args.content_profile, args.random_seed,
                )
