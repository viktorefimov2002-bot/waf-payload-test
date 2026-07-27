#!/usr/bin/env python3
"""Generate byte-exact HTTP request cases for WAF parser and memory testing."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import random
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlencode
from xml.sax.saxutils import escape as xml_escape

try:
    import brotli  # type: ignore
except ImportError:  # pragma: no cover
    brotli = None


@dataclass(frozen=True)
class Document:
    body: str | bytes
    media_type: str
    structure: str
    validity: str
    metrics: dict[str, int | str | bool]


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


def corrupt_compressed(data: bytes, mode: str) -> bytes:
    if mode == "valid":
        return data
    if not data:
        return data
    if mode == "truncated":
        return data[: max(1, len(data) // 2)]
    if mode == "bad-tail":
        tail = bytearray(data)
        for index in range(max(0, len(tail) - min(8, len(tail))), len(tail)):
            tail[index] ^= 0xFF
        return bytes(tail)
    if mode == "bitflip":
        mutated = bytearray(data)
        mutated[len(mutated) // 2] ^= 0x20
        return bytes(mutated)
    raise ValueError(f"Unsupported corruption mode: {mode}")


def make_filler(size: int, kind: str, seed: int) -> str:
    if size <= 0:
        return ""
    if kind == "repeated":
        return "A" * size
    if kind == "unicode":
        pattern = "Привет世界🙂e\u0301\u200d"
        return (pattern * ((size // len(pattern)) + 1))[:size]
    if kind == "random-ascii":
        rng = random.Random(seed + size)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        return "".join(rng.choice(alphabet) for _ in range(size))
    if kind == "numeric":
        pattern = "1234567890"
        return (pattern * ((size // len(pattern)) + 1))[:size]
    raise ValueError(f"Unsupported filler kind: {kind}")


def nested_json(value: str, depth: int) -> Any:
    node: Any = value
    for index in range(depth):
        node = {f"level_{index}": node}
    return node


def build_json(value: str, structure: str, depth: int, width: int, fields: int) -> Document:
    if structure == "single":
        obj: Any = {"input": value}
        metrics = {"depth": 1, "width": 1, "fields": 1}
    elif structure == "deep":
        obj = nested_json(value, depth)
        metrics = {"depth": depth, "width": 1, "fields": depth}
    elif structure == "wide":
        obj = {f"field_{index:06d}": value for index in range(width)}
        metrics = {"depth": 1, "width": width, "fields": width}
    elif structure == "array":
        obj = [value for _ in range(width)]
        metrics = {"depth": 1, "width": width, "fields": width}
    elif structure == "duplicate-keys":
        pairs = ",".join(f'"dup":{json.dumps(value, ensure_ascii=False)}' for _ in range(fields))
        return Document("{" + pairs + "}", "application/json", structure, "valid", {"depth": 1, "width": fields, "fields": fields})
    elif structure == "many-fields":
        obj = {f"k{index}": index for index in range(fields)}
        obj["input"] = value
        metrics = {"depth": 1, "width": fields + 1, "fields": fields + 1}
    elif structure == "truncated":
        valid = json.dumps({"input": value}, ensure_ascii=False, separators=(",", ":"))
        return Document(valid[:-1], "application/json", structure, "invalid", {"depth": 1, "width": 1, "fields": 1})
    elif structure == "trailing-garbage":
        valid = json.dumps({"input": value}, ensure_ascii=False, separators=(",", ":"))
        return Document(valid + " trailing", "application/json", structure, "invalid", {"depth": 1, "width": 1, "fields": 1})
    else:
        raise ValueError(f"Unsupported JSON structure: {structure}")
    body = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return Document(body, "application/json", structure, "valid", metrics)


def build_form(value: str, structure: str, fields: int) -> Document:
    if structure == "single":
        body = urlencode({"input": value})
        count = 1
        validity = "valid"
    elif structure == "many-fields":
        values = [(f"k{index}", str(index)) for index in range(fields)]
        values.append(("input", value))
        body = urlencode(values)
        count = fields + 1
        validity = "valid"
    elif structure == "repeated-keys":
        body = urlencode([("input", value) for _ in range(fields)])
        count = fields
        validity = "valid"
    elif structure == "empty-pairs":
        body = "&".join(["=", "a=", "=b", "input=" + value])
        count = 4
        validity = "valid"
    elif structure == "invalid-percent":
        body = "input=%E2%82&bad=%ZZ&tail=%"
        count = 3
        validity = "invalid"
    else:
        raise ValueError(f"Unsupported form structure: {structure}")
    return Document(body, "application/x-www-form-urlencoded", structure, validity, {"fields": count, "depth": 1, "width": count})


def build_xml(value: str, structure: str, depth: int, width: int) -> Document:
    safe = xml_escape(value)
    if structure == "single":
        body = f'<?xml version="1.0"?><root><input>{safe}</input></root>'
        validity = "valid"
        metrics = {"depth": 2, "width": 1, "fields": 1}
    elif structure == "deep":
        opening = "".join(f"<level{index}>" for index in range(depth))
        closing = "".join(f"</level{index}>" for index in reversed(range(depth)))
        body = f'<?xml version="1.0"?><root>{opening}{safe}{closing}</root>'
        validity = "valid"
        metrics = {"depth": depth + 1, "width": 1, "fields": depth}
    elif structure == "wide":
        children = "".join(f"<item id=\"{index}\">{safe}</item>" for index in range(width))
        body = f'<?xml version="1.0"?><root>{children}</root>'
        validity = "valid"
        metrics = {"depth": 2, "width": width, "fields": width}
    elif structure == "attributes":
        attrs = " ".join(f'a{index}="{index}"' for index in range(width))
        body = f'<?xml version="1.0"?><root {attrs}><input>{safe}</input></root>'
        validity = "valid"
        metrics = {"depth": 2, "width": width, "fields": width}
    elif structure == "truncated":
        body = f'<?xml version="1.0"?><root><input>{safe}</input>'
        validity = "invalid"
        metrics = {"depth": 2, "width": 1, "fields": 1}
    else:
        raise ValueError(f"Unsupported XML structure: {structure}")
    return Document(body, "application/xml", structure, validity, metrics)


def build_multipart(value: str, structure: str, fields: int, boundary: str) -> Document:
    line = "\r\n"
    parts: list[str] = []
    count = 1 if structure == "single" else fields
    for index in range(count):
        name = "input" if structure == "single" else f"field_{index}"
        parts.extend([
            f"--{boundary}",
            f'Content-Disposition: form-data; name="{name}"',
            "",
            value if structure == "single" else f"{value}-{index}",
        ])
    parts.append(f"--{boundary}--")
    parts.append("")
    body = line.join(parts)
    validity = "valid"
    if structure == "missing-close":
        body = body.rsplit(f"--{boundary}--", 1)[0]
        validity = "invalid"
    elif structure == "lf-only":
        body = body.replace("\r\n", "\n")
    return Document(body, f"multipart/form-data; boundary={boundary}", structure, validity, {"fields": count, "depth": 1, "width": count})


def build_document(fmt: str, value: str, structure: str, depth: int, width: int, fields: int, boundary: str) -> Document:
    if fmt == "json":
        return build_json(value, structure, depth, width, fields)
    if fmt == "form":
        return build_form(value, structure, fields)
    if fmt == "xml":
        return build_xml(value, structure, depth, width)
    if fmt == "multipart":
        return build_multipart(value, structure, fields, boundary)
    if fmt == "text":
        return Document(value, "text/plain", "single", "valid", {"depth": 1, "width": 1, "fields": 1})
    if fmt == "octet-stream":
        return Document(value.encode("utf-8"), "application/octet-stream", "single", "valid", {"depth": 1, "width": 1, "fields": 1})
    raise ValueError(f"Unsupported format: {fmt}")


STRUCTURES = {
    "json": ["single", "deep", "wide", "array", "many-fields", "duplicate-keys", "truncated", "trailing-garbage"],
    "form": ["single", "many-fields", "repeated-keys", "empty-pairs", "invalid-percent"],
    "xml": ["single", "deep", "wide", "attributes", "truncated"],
    "multipart": ["single", "many-fields", "missing-close", "lf-only"],
    "text": ["single"],
    "octet-stream": ["single"],
}


def iter_cases(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    case_number = 0
    compressions = list(args.compressions)
    if brotli is None and "br" in compressions:
        compressions.remove("br")
        print("Warning: brotli is unavailable; br cases are skipped.")

    for fmt in args.formats:
        for structure in STRUCTURES[fmt]:
            for charset in args.charsets:
                if fmt == "octet-stream" and charset != "utf-8":
                    continue
                for bom in args.bom:
                    if bom and charset not in {"utf-8", "utf-16le", "utf-16be", "utf-32le", "utf-32be"}:
                        continue
                    for filler_kind in args.filler_kinds:
                        for requested_size in args.sizes:
                            logical_value = make_filler(requested_size, filler_kind, args.seed) + args.payload
                            boundary = f"----WAFPayloadBoundary{args.seed:08d}"
                            document = build_document(fmt, logical_value, structure, args.depth, args.width, args.fields, boundary)
                            serialized = document.body if isinstance(document.body, bytes) else encode_text(document.body, charset, bom=bom)

                            for compression in compressions:
                                compressed = compress_body(serialized, compression)
                                corruption_modes = ["valid"]
                                if compression != "none" and args.include_corrupt_compression:
                                    corruption_modes += ["truncated", "bad-tail", "bitflip"]

                                for corruption in corruption_modes:
                                    wire_body = corrupt_compressed(compressed, corruption)
                                    case_number += 1
                                    case_id = f"case-{case_number:06d}-{fmt}-{structure}-{charset}-{compression}-{corruption}"
                                    headers = {
                                        "Content-Type": document.media_type if fmt in {"octet-stream", "multipart"} else f"{document.media_type}; charset={charset}",
                                        "X-WAF-Test-Case-ID": case_id,
                                    }
                                    if compression != "none":
                                        headers["Content-Encoding"] = "deflate" if compression == "raw-deflate" else compression
                                    metadata = {
                                        "format": fmt,
                                        "structure": document.structure,
                                        "validity": document.validity if corruption == "valid" else "invalid-compression",
                                        "charset": charset,
                                        "bom": bom,
                                        "filler_kind": filler_kind,
                                        "requested_filler_chars": requested_size,
                                        "compression": compression,
                                        "compression_corruption": corruption,
                                        "seed": args.seed,
                                        **document.metrics,
                                    }
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
                                        "expansion_ratio": round(len(serialized) / max(1, len(wire_body)), 4),
                                        "metadata": metadata,
                                    }


def parse_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate byte-exact WAF request cases")
    parser.add_argument("--output", default="payloads.json", help="Output JSON manifest")
    parser.add_argument("--payload", default="normal-client-value", help="Suffix included in every logical value")
    parser.add_argument("--path", default="/endpoint", help="Request path stored in every case")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sizes", type=int, nargs="+", default=[0, 100, 1000, 10000])
    parser.add_argument("--formats", nargs="+", choices=list(STRUCTURES), default=list(STRUCTURES))
    parser.add_argument("--charsets", nargs="+", default=["utf-8", "utf-16le", "utf-16be"])
    parser.add_argument("--compressions", nargs="+", choices=["none", "gzip", "deflate", "raw-deflate", "br"], default=["none", "gzip", "deflate"])
    parser.add_argument("--filler-kinds", nargs="+", choices=["repeated", "random-ascii", "unicode", "numeric"], default=["repeated", "random-ascii", "unicode"])
    parser.add_argument("--bom", nargs="+", type=parse_bool, default=[False, True], metavar="BOOL")
    parser.add_argument("--depth", type=int, default=64)
    parser.add_argument("--width", type=int, default=256)
    parser.add_argument("--fields", type=int, default=512)
    parser.add_argument("--include-corrupt-compression", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cases = list(iter_cases(args))
    output = Path(args.output)
    output.write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    valid = sum(case["metadata"]["validity"] == "valid" for case in cases)
    invalid = len(cases) - valid
    print(f"Generated {len(cases)} cases in {output} ({valid} valid, {invalid} invalid)")


if __name__ == "__main__":
    main()
