#!/usr/bin/env python3
"""Generate byte-exact HTTP request cases for WAF parser/memory testing."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import random
import zlib
from pathlib import Path
from typing import Any, Iterable

try:
    import brotli  # type: ignore
except ImportError:  # pragma: no cover
    brotli = None


def encode_text(text: str, charset: str, bom: bool = False) -> bytes:
    normalized = charset.lower()
    data = text.encode(normalized)
    if not bom:
        return data
    prefixes = {
        "utf-8": b"\xef\xbb\xbf",
        "utf-16le": b"\xff\xfe",
        "utf-16be": b"\xfe\xff",
        "utf-32le": b"\xff\xfe\x00\x00",
        "utf-32be": b"\x00\x00\xfe\xff",
    }
    return prefixes.get(normalized, b"") + data


def compress_body(data: bytes, compression: str) -> bytes:
    if compression == "none":
        return data
    if compression == "gzip":
        return gzip.compress(data, compresslevel=6, mtime=0)
    if compression == "deflate":
        return zlib.compress(data, level=6)
    if compression == "raw-deflate":
        compressor = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
        return compressor.compress(data) + compressor.flush()
    if compression == "br":
        if brotli is None:
            raise RuntimeError("brotli module is not installed")
        return brotli.compress(data)
    raise ValueError(f"Unsupported compression: {compression}")


def make_filler(size: int, kind: str, seed: int) -> str:
    if size <= 0:
        return ""
    if kind == "repeated":
        return "A" * size
    if kind == "unicode":
        pattern = "Привет世界🙂"
        return (pattern * ((size // len(pattern)) + 1))[:size]
    if kind == "random-ascii":
        rng = random.Random(seed)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        return "".join(rng.choice(alphabet) for _ in range(size))
    raise ValueError(f"Unsupported filler kind: {kind}")


def serialize_document(fmt: str, value: str) -> tuple[bytes | str, str]:
    if fmt == "json":
        return json.dumps({"input": value}, ensure_ascii=False, separators=(",", ":")), "application/json"
    if fmt == "form":
        from urllib.parse import urlencode
        return urlencode({"input": value}), "application/x-www-form-urlencoded"
    if fmt == "text":
        return value, "text/plain"
    if fmt == "octet-stream":
        return value.encode("utf-8"), "application/octet-stream"
    raise ValueError(f"Unsupported format: {fmt}")


def iter_cases(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    case_number = 0
    compressions = list(args.compressions)
    if brotli is None and "br" in compressions:
        compressions.remove("br")
        print("Warning: brotli is unavailable; br cases are skipped.")

    for fmt in args.formats:
        for charset in args.charsets:
            if fmt == "octet-stream" and charset != "utf-8":
                continue
            for bom in args.bom:
                if bom and charset not in {"utf-8", "utf-16le", "utf-16be", "utf-32le", "utf-32be"}:
                    continue
                for filler_kind in args.filler_kinds:
                    for requested_size in args.sizes:
                        logical_value = make_filler(requested_size, filler_kind, args.seed) + args.payload
                        document, media_type = serialize_document(fmt, logical_value)
                        if isinstance(document, bytes):
                            serialized = document
                        else:
                            serialized = encode_text(document, charset, bom=bom)
                        for compression in compressions:
                            wire_body = compress_body(serialized, compression)
                            case_number += 1
                            case_id = (
                                f"case-{case_number:06d}-{fmt}-{charset}-"
                                f"{'bom' if bom else 'nobom'}-{filler_kind}-{requested_size}-{compression}"
                            )
                            headers = {
                                "Content-Type": media_type if fmt == "octet-stream" else f"{media_type}; charset={charset}",
                                "X-WAF-Test-Case-ID": case_id,
                            }
                            if compression != "none":
                                headers["Content-Encoding"] = "deflate" if compression == "raw-deflate" else compression
                            yield {
                                "id": case_id,
                                "method": "POST",
                                "path": args.path,
                                "headers": headers,
                                "body_base64": base64.b64encode(wire_body).decode("ascii"),
                                "sha256": hashlib.sha256(wire_body).hexdigest(),
                                "logical_size": len(logical_value.encode("utf-8")),
                                "serialized_size": len(serialized),
                                "wire_body_size": len(wire_body),
                                "metadata": {
                                    "format": fmt,
                                    "charset": charset,
                                    "bom": bom,
                                    "filler_kind": filler_kind,
                                    "requested_filler_chars": requested_size,
                                    "compression": compression,
                                    "validity": "valid",
                                    "seed": args.seed,
                                },
                            }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate byte-exact WAF request cases")
    parser.add_argument("--output", default="payloads.json", help="Output JSON manifest")
    parser.add_argument("--payload", default="normal-client-value", help="Suffix included in every logical value")
    parser.add_argument("--path", default="/endpoint", help="Request path stored in every case")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sizes", type=int, nargs="+", default=[0, 100, 1000, 10000, 50000])
    parser.add_argument("--formats", nargs="+", choices=["json", "form", "text", "octet-stream"], default=["json", "form", "text", "octet-stream"])
    parser.add_argument("--charsets", nargs="+", default=["utf-8", "utf-16le", "utf-16be"])
    parser.add_argument("--compressions", nargs="+", choices=["none", "gzip", "deflate", "raw-deflate", "br"], default=["none", "gzip", "deflate"])
    parser.add_argument("--filler-kinds", nargs="+", choices=["repeated", "random-ascii", "unicode"], default=["repeated", "random-ascii", "unicode"])
    parser.add_argument("--bom", nargs="+", type=lambda value: value.lower() in {"1", "true", "yes"}, default=[False, True], metavar="BOOL")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cases = list(iter_cases(args))
    output = Path(args.output)
    output.write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Generated {len(cases)} cases in {output}")


if __name__ == "__main__":
    main()
