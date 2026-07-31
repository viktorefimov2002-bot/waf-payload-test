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
from urllib.parse import quote, urlencode
from xml.sax.saxutils import escape as xml_escape

try:
    import brotli  # type: ignore
except ImportError:  # pragma: no cover
    brotli = None

BOUNDARY_SIZES = [0, 1, 15, 16, 17, 255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192, 8193, 65535, 65536, 65537]
BASE_STRUCTURES = {
    "json": ["single", "deep", "wide", "array", "many-fields", "duplicate-keys", "truncated", "trailing-garbage"],
    "form": ["single", "many-fields", "repeated-keys", "empty-pairs", "invalid-percent"],
    "xml": ["single", "deep", "wide", "attributes", "truncated"],
    "multipart": ["single", "many-fields", "missing-close", "lf-only"],
    "text": ["single"],
    "octet-stream": ["single"],
}
PHASE1_STRUCTURES = {
    "json": ["deep-wide", "array-objects", "array-mixed", "long-field-name", "many-long-field-names", "escape-heavy"],
    "form": ["long-field-name", "many-long-field-names", "mixed-types", "escape-heavy"],
    "xml": ["deep-wide", "long-element-name", "long-attribute-name", "escape-heavy"],
    "multipart": ["many-short-parts", "empty-parts", "long-name", "long-filename", "long-boundary", "boundary-collision"],
    "text": ["escape-heavy"],
    "octet-stream": [],
}
STRUCTURES = {fmt: BASE_STRUCTURES[fmt] + PHASE1_STRUCTURES[fmt] for fmt in BASE_STRUCTURES}
RECOMMENDED_VALUE_ENCODINGS = {
    "json": ["plain", "base64", "url", "json-unicode-escape"],
    "form": ["plain", "double-url", "base64"],
    "xml": ["plain", "base64", "url"],
    "multipart": ["plain", "base64"],
    "text": ["plain", "base64", "url"],
    "octet-stream": ["plain", "base64"],
}
ALL_VALUE_ENCODINGS = sorted({x for values in RECOMMENDED_VALUE_ENCODINGS.values() for x in values})


@dataclass(frozen=True)
class Document:
    body: str | bytes
    media_type: str
    structure: str
    validity: str
    metrics: dict[str, int | str | bool]


def repeat_to_length(pattern: str, size: int) -> str:
    return "" if size <= 0 else (pattern * (size // max(1, len(pattern)) + 1))[:size]


def make_filler(size: int, kind: str, seed: int) -> str:
    if size <= 0:
        return ""
    patterns = {
        "repeated": "A",
        "unicode": "Привет世界🙂e\u0301\u200d",
        "numeric": "1234567890",
        "escape-json": '"\\/\n\r\t\b\f',
        "escape-xml": "<&>\"'",
        "escape-form": " +%&=;/?:@",
    }
    if kind in patterns:
        return repeat_to_length(patterns[kind], size)
    if kind == "random-ascii":
        rng = random.Random(seed + size)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        return "".join(rng.choice(alphabet) for _ in range(size))
    raise ValueError(f"Unsupported filler kind: {kind}")


def encode_text(text: str, charset: str, bom: bool = False) -> bytes:
    normalized = charset.lower()
    data = text.encode(normalized)
    prefixes = {
        "utf-8": b"\xef\xbb\xbf",
        "utf-16le": b"\xff\xfe",
        "utf-16be": b"\xfe\xff",
        "utf-32le": b"\xff\xfe\x00\x00",
        "utf-32be": b"\x00\x00\xfe\xff",
    }
    return (prefixes.get(normalized, b"") if bom else b"") + data


def encode_document(body: str | bytes, declared: str, bom: bool, mode: str) -> tuple[bytes, str]:
    if isinstance(body, bytes):
        return body, "binary"
    if mode == "valid":
        return encode_text(body, declared, bom), declared
    if mode == "mismatch":
        actual = "utf-16le" if declared.lower() != "utf-16le" else "utf-8"
        return encode_text(body, actual), actual
    if mode == "invalid-tail":
        return encode_text(body, declared, bom) + b"\xff\xfe\xc0\xaf", declared
    if mode == "truncated-code-unit":
        data = encode_text(body, declared, bom)
        return (data[:-1] if data else b"\xff"), declared
    raise ValueError(f"Unsupported charset mode: {mode}")


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
    if mode == "valid" or not data:
        return data
    if mode == "truncated":
        return data[: max(1, len(data) // 2)]
    value = bytearray(data)
    if mode == "bad-tail":
        for index in range(max(0, len(value) - 8), len(value)):
            value[index] ^= 0xFF
    elif mode == "bitflip":
        value[len(value) // 2] ^= 0x20
    else:
        raise ValueError(f"Unsupported corruption mode: {mode}")
    return bytes(value)


def value_encodings_for(fmt: str, structure: str, args: argparse.Namespace) -> list[str]:
    if structure == "invalid-percent":
        return ["plain"]
    if args.value_encodings:
        selected = [item for item in args.value_encodings if item in RECOMMENDED_VALUE_ENCODINGS[fmt]]
        if not selected:
            raise ValueError(f"No requested value encodings are valid for format {fmt}")
        return selected
    return list(RECOMMENDED_VALUE_ENCODINGS[fmt]) if args.value_encoding_profile == "recommended" else ["plain"]


def transform_value(value: str, encoding: str) -> str:
    if encoding in {"plain", "json-unicode-escape"}:
        return value
    if encoding == "base64":
        return base64.b64encode(value.encode()).decode()
    if encoding in {"url", "double-url"}:
        return quote(value, safe="")
    raise ValueError(f"Unsupported value encoding: {encoding}")


def long_name(length: int, index: int = 0) -> str:
    suffix = f"_{index:08d}"
    return (("field_" + "a" * max(0, length))[: max(0, length - len(suffix))] + suffix)[:length]


def nested_json(value: Any, depth: int) -> Any:
    node = value
    for index in range(depth):
        node = {f"level_{index}": node}
    return node


def build_json(value: str, structure: str, depth: int, width: int, fields: int, name_length: int, ensure_ascii: bool) -> Document:
    dumps = lambda obj: json.dumps(obj, ensure_ascii=ensure_ascii, separators=(",", ":"))
    metrics: dict[str, int | str | bool]
    if structure == "single":
        obj, metrics = {"input": value}, {"depth": 1, "width": 1, "fields": 1}
    elif structure == "deep":
        obj, metrics = nested_json(value, depth), {"depth": depth, "width": 1, "fields": depth}
    elif structure == "wide":
        obj, metrics = {f"field_{i:06d}": value for i in range(width)}, {"depth": 1, "width": width, "fields": width}
    elif structure == "array":
        obj, metrics = [value for _ in range(width)], {"depth": 1, "width": width, "fields": width}
    elif structure == "many-fields":
        obj = {f"k{i}": i for i in range(fields)}
        obj["input"] = value
        metrics = {"depth": 1, "width": fields + 1, "fields": fields + 1}
    elif structure == "duplicate-keys":
        pairs = ",".join(f'"dup":{dumps(value)}' for _ in range(fields))
        return Document("{" + pairs + "}", "application/json", structure, "valid", {"depth": 1, "width": fields, "fields": fields})
    elif structure == "deep-wide":
        node: Any = value
        for level in range(depth):
            siblings = {f"s{level}_{i}": value for i in range(max(0, width - 1))}
            siblings[f"next_{level}"] = node
            node = siblings
        obj, metrics = node, {"depth": depth, "width": width, "fields": depth * width}
    elif structure == "array-objects":
        obj, metrics = [{"index": i, "value": value} for i in range(width)], {"depth": 2, "width": width, "fields": width * 2}
    elif structure == "array-mixed":
        templates: list[Any] = [value, None, True, 0, {"value": value}, [value]]
        obj = [templates[i % len(templates)] for i in range(width)]
        metrics = {"depth": 2, "width": width, "fields": width}
    elif structure == "long-field-name":
        obj, metrics = {long_name(name_length): value}, {"depth": 1, "width": 1, "fields": 1, "field_name_length": name_length}
    elif structure == "many-long-field-names":
        obj, metrics = {long_name(name_length, i): value for i in range(fields)}, {"depth": 1, "width": fields, "fields": fields, "field_name_length": name_length}
    elif structure == "escape-heavy":
        obj, metrics = {"input": repeat_to_length('"\\/\n\r\t\b\f\u0041', max(1, len(value)))}, {"depth": 1, "width": 1, "fields": 1, "escape_heavy": True}
    elif structure == "truncated":
        valid = dumps({"input": value})
        return Document(valid[:-1], "application/json", structure, "invalid", {"depth": 1, "width": 1, "fields": 1})
    elif structure == "trailing-garbage":
        valid = dumps({"input": value})
        return Document(valid + " trailing", "application/json", structure, "invalid", {"depth": 1, "width": 1, "fields": 1})
    else:
        raise ValueError(f"Unsupported JSON structure: {structure}")
    return Document(dumps(obj), "application/json", structure, "valid", metrics)


def build_form(value: str, structure: str, fields: int, name_length: int) -> Document:
    if structure == "single":
        pairs = [("input", value)]
    elif structure == "many-fields":
        pairs = [(f"k{i}", str(i)) for i in range(fields)] + [("input", value)]
    elif structure == "repeated-keys":
        pairs = [("input", value) for _ in range(fields)]
    elif structure == "empty-pairs":
        return Document("&".join(["=", "a=", "=b", "input=" + value]), "application/x-www-form-urlencoded", structure, "valid", {"fields": 4, "depth": 1, "width": 4})
    elif structure == "invalid-percent":
        return Document("input=%E2%82&bad=%ZZ&tail=%", "application/x-www-form-urlencoded", structure, "invalid", {"fields": 3, "depth": 1, "width": 3})
    elif structure == "long-field-name":
        pairs = [(long_name(name_length), value)]
    elif structure == "many-long-field-names":
        pairs = [(long_name(name_length, i), value) for i in range(fields)]
    elif structure == "mixed-types":
        pairs = [("input", value), ("input[]", value), ("input[key]", value), ("input", "scalar")]
    elif structure == "escape-heavy":
        pairs = [("input", repeat_to_length(" +%&=;/?:@", max(1, len(value))))]
    else:
        raise ValueError(f"Unsupported form structure: {structure}")
    metrics: dict[str, int | str | bool] = {"fields": len(pairs), "depth": 1, "width": len(pairs)}
    if "long-field" in structure:
        metrics["field_name_length"] = name_length
    return Document(urlencode(pairs), "application/x-www-form-urlencoded", structure, "valid", metrics)


def build_xml(value: str, structure: str, depth: int, width: int, name_length: int) -> Document:
    safe = xml_escape(value, {'"': "&quot;", "'": "&apos;"})
    validity = "valid"
    if structure == "single":
        body = f'<?xml version="1.0"?><root><input>{safe}</input></root>'
        metrics = {"depth": 2, "width": 1, "fields": 1}
    elif structure == "deep":
        opening = "".join(f"<level{i}>" for i in range(depth))
        closing = "".join(f"</level{i}>" for i in reversed(range(depth)))
        body = f'<?xml version="1.0"?><root>{opening}{safe}{closing}</root>'
        metrics = {"depth": depth + 1, "width": 1, "fields": depth}
    elif structure == "wide":
        children = "".join(f'<item id="{i}">{safe}</item>' for i in range(width))
        body = f'<?xml version="1.0"?><root>{children}</root>'
        metrics = {"depth": 2, "width": width, "fields": width}
    elif structure == "attributes":
        attrs = " ".join(f'a{i}="{i}"' for i in range(width))
        body = f'<?xml version="1.0"?><root {attrs}><input>{safe}</input></root>'
        metrics = {"depth": 2, "width": width, "fields": width}
    elif structure == "deep-wide":
        opening: list[str] = []
        closing: list[str] = []
        for level in range(depth):
            opening.append(f"<level{level}>")
            opening.extend(f"<sibling>{safe}</sibling>" for _ in range(max(0, width - 1)))
            closing.insert(0, f"</level{level}>")
        body = '<?xml version="1.0"?><root>' + "".join(opening) + safe + "".join(closing) + "</root>"
        metrics = {"depth": depth + 1, "width": width, "fields": depth * width}
    elif structure == "long-element-name":
        name = "e" * max(1, name_length)
        body = f'<?xml version="1.0"?><root><{name}>{safe}</{name}></root>'
        metrics = {"depth": 2, "width": 1, "fields": 1, "field_name_length": name_length}
    elif structure == "long-attribute-name":
        name = "a" * max(1, name_length)
        body = f'<?xml version="1.0"?><root {name}="1"><input>{safe}</input></root>'
        metrics = {"depth": 2, "width": 1, "fields": 1, "field_name_length": name_length}
    elif structure == "escape-heavy":
        escaped = "&amp;&lt;&gt;&quot;&apos;&#65;&#x41;" * max(1, len(value) // 8)
        body = f'<?xml version="1.0"?><root><input>{escaped}</input></root>'
        metrics = {"depth": 2, "width": 1, "fields": 1, "escape_heavy": True}
    elif structure == "truncated":
        body = f'<?xml version="1.0"?><root><input>{safe}</input>'
        validity = "invalid"
        metrics = {"depth": 2, "width": 1, "fields": 1}
    else:
        raise ValueError(f"Unsupported XML structure: {structure}")
    return Document(body, "application/xml", structure, validity, metrics)


def multipart_body(parts: list[tuple[str, str | None, str]], boundary: str, line: str = "\r\n", close: bool = True) -> str:
    output: list[str] = []
    for name, filename, content in parts:
        output.append(f"--{boundary}")
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        output.extend([disposition, "", content])
    if close:
        output.extend([f"--{boundary}--", ""])
    return line.join(output)


def build_multipart(value: str, structure: str, fields: int, boundary: str, name_length: int) -> Document:
    validity = "valid"
    line = "\r\n"
    if structure == "single":
        parts = [("input", None, value)]
    elif structure in {"many-fields", "many-short-parts"}:
        parts = [(f"field_{i}", None, value if structure == "many-fields" else str(i % 10)) for i in range(fields)]
    elif structure == "empty-parts":
        parts = [(f"field_{i}", None, "") for i in range(fields)]
    elif structure == "long-name":
        parts = [(long_name(name_length), None, value)]
    elif structure == "long-filename":
        parts = [("upload", "f" * max(1, name_length), value)]
    elif structure == "long-boundary":
        parts = [("input", None, value)]
    elif structure == "boundary-collision":
        parts = [("input", None, value + f"\r\n--{boundary[:-1]}X\r\n" + value)]
    elif structure == "missing-close":
        parts = [(f"field_{i}", None, value) for i in range(fields)]
        validity = "invalid"
        return Document(multipart_body(parts, boundary, close=False), f"multipart/form-data; boundary={boundary}", structure, validity, {"fields": fields, "depth": 1, "width": fields})
    elif structure == "lf-only":
        parts = [(f"field_{i}", None, value) for i in range(fields)]
        line = "\n"
    else:
        raise ValueError(f"Unsupported multipart structure: {structure}")
    metrics: dict[str, int | str | bool] = {"fields": len(parts), "depth": 1, "width": len(parts), "boundary_length": len(boundary)}
    if structure in {"long-name", "long-filename"}:
        metrics["field_name_length"] = name_length
    return Document(multipart_body(parts, boundary, line=line), f"multipart/form-data; boundary={boundary}", structure, validity, metrics)


def build_document(fmt: str, value: str, value_encoding: str, structure: str, depth: int, width: int, fields: int, boundary: str, name_length: int) -> Document:
    if fmt == "json":
        return build_json(value, structure, depth, width, fields, name_length, value_encoding == "json-unicode-escape")
    if fmt == "form":
        return build_form(value, structure, fields, name_length)
    if fmt == "xml":
        return build_xml(value, structure, depth, width, name_length)
    if fmt == "multipart":
        return build_multipart(value, structure, fields, boundary, name_length)
    if fmt == "text":
        text = repeat_to_length('"\\/<>&%\n\r\t', max(1, len(value))) if structure == "escape-heavy" else value
        return Document(text, "text/plain", structure, "valid", {"depth": 1, "width": 1, "fields": 1, "escape_heavy": structure == "escape-heavy"})
    if fmt == "octet-stream":
        return Document(value.encode(), "application/octet-stream", "single", "valid", {"depth": 1, "width": 1, "fields": 1})
    raise ValueError(f"Unsupported format: {fmt}")


def structures_for(fmt: str, args: argparse.Namespace) -> list[str]:
    return BASE_STRUCTURES[fmt] + (PHASE1_STRUCTURES[fmt] if args.stress_profile == "phase1" else [])


def iter_cases(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    case_number = 0
    compressions = list(args.compressions)
    if brotli is None and "br" in compressions:
        compressions.remove("br")
        print("Warning: brotli is unavailable; br cases are skipped.")
    for fmt in args.formats:
        for structure in structures_for(fmt, args):
            name_lengths = args.field_name_lengths if structure in {"long-field-name", "many-long-field-names", "long-element-name", "long-attribute-name", "long-name", "long-filename"} else [0]
            boundary_lengths = args.multipart_boundary_lengths if structure == "long-boundary" else [0]
            for name_length in name_lengths:
                for requested_boundary_length in boundary_lengths:
                    for charset in args.charsets:
                        if fmt == "octet-stream" and charset != "utf-8":
                            continue
                        for charset_mode in args.charset_modes:
                            if fmt == "octet-stream" and charset_mode != "valid":
                                continue
                            for bom in args.bom:
                                for filler_kind in args.filler_kinds:
                                    for requested_size in args.sizes:
                                        logical = make_filler(requested_size, filler_kind, args.seed) + args.payload
                                        boundary = "B" * max(1, requested_boundary_length) if requested_boundary_length else f"----WAFPayloadBoundary{args.seed:08d}"
                                        for value_encoding in value_encodings_for(fmt, structure, args):
                                            encoded = transform_value(logical, value_encoding)
                                            document = build_document(fmt, encoded, value_encoding, structure, args.depth, args.width, args.fields, boundary, name_length)
                                            serialized, actual_charset = encode_document(document.body, charset, bom, charset_mode)
                                            for compression in compressions:
                                                compressed = compress_body(serialized, compression)
                                                modes = ["valid"] + (["truncated", "bad-tail", "bitflip"] if compression != "none" and args.include_corrupt_compression else [])
                                                for corruption in modes:
                                                    wire = corrupt_compressed(compressed, corruption)
                                                    case_number += 1
                                                    case_id = f"case-{case_number:06d}-{fmt}-{structure}-{value_encoding}-{charset}-{charset_mode}-{compression}-{corruption}"
                                                    content_type = document.media_type if fmt in {"octet-stream", "multipart"} else f"{document.media_type}; charset={charset}"
                                                    headers = {"Content-Type": content_type, "X-WAF-Test-Case-ID": case_id}
                                                    if compression != "none":
                                                        headers["Content-Encoding"] = "deflate" if compression == "raw-deflate" else compression
                                                    validity = "invalid-compression" if corruption != "valid" else "invalid-charset" if charset_mode != "valid" else document.validity
                                                    metadata = {
                                                        "format": fmt,
                                                        "structure": document.structure,
                                                        "validity": validity,
                                                        "value_encoding": value_encoding,
                                                        "charset": charset,
                                                        "actual_charset": actual_charset,
                                                        "charset_mode": charset_mode,
                                                        "bom": bom,
                                                        "filler_kind": filler_kind,
                                                        "requested_filler_chars": requested_size,
                                                        "encoded_value_utf8_size": len(encoded.encode()),
                                                        "compression": compression,
                                                        "compression_corruption": corruption,
                                                        "seed": args.seed,
                                                        "stress_profile": args.stress_profile,
                                                        **document.metrics,
                                                    }
                                                    yield {
                                                        "id": case_id,
                                                        "method": "POST",
                                                        "path": args.path,
                                                        "headers": headers,
                                                        "body_base64": base64.b64encode(wire).decode(),
                                                        "sha256": hashlib.sha256(wire).hexdigest(),
                                                        "logical_size": len(logical.encode()),
                                                        "serialized_size": len(serialized),
                                                        "wire_body_size": len(wire),
                                                        "expansion_ratio": round(len(serialized) / max(1, len(wire)), 4),
                                                        "metadata": metadata,
                                                    }


def parse_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate byte-exact WAF request cases")
    parser.add_argument("--output", default="payloads.json")
    parser.add_argument("--payload", default="normal-client-value")
    parser.add_argument("--path", default="/endpoint")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--stress-profile", choices=["baseline", "phase1"], default="baseline")
    parser.add_argument("--size-profile", choices=["default", "boundaries"], default="default")
    parser.add_argument("--sizes", type=int, nargs="+")
    parser.add_argument("--formats", nargs="+", choices=list(STRUCTURES), default=list(STRUCTURES))
    parser.add_argument("--charsets", nargs="+", default=["utf-8", "utf-16le", "utf-16be"])
    parser.add_argument("--charset-modes", nargs="+", choices=["valid", "mismatch", "invalid-tail", "truncated-code-unit"], default=["valid"])
    parser.add_argument("--compressions", nargs="+", choices=["none", "gzip", "deflate", "raw-deflate", "br"], default=["none", "gzip", "deflate"])
    parser.add_argument("--filler-kinds", nargs="+", choices=["repeated", "random-ascii", "unicode", "numeric", "escape-json", "escape-xml", "escape-form"], default=["repeated", "random-ascii", "unicode"])
    parser.add_argument("--bom", nargs="+", type=parse_bool, default=[False, True])
    parser.add_argument("--value-encoding-profile", choices=["plain", "recommended"], default="plain")
    parser.add_argument("--value-encodings", nargs="+", choices=ALL_VALUE_ENCODINGS)
    parser.add_argument("--depth", type=int, default=64)
    parser.add_argument("--width", type=int, default=256)
    parser.add_argument("--fields", type=int, default=512)
    parser.add_argument("--field-name-lengths", type=int, nargs="+", default=[16, 256, 1024, 8192])
    parser.add_argument("--multipart-boundary-lengths", type=int, nargs="+", default=[70, 256, 1024, 8192])
    parser.add_argument("--include-corrupt-compression", action="store_true")
    args = parser.parse_args()
    if args.sizes is None:
        args.sizes = BOUNDARY_SIZES if args.size_profile == "boundaries" else [0, 100, 1000, 10000]
    return args


def main() -> None:
    args = parse_args()
    cases = list(iter_cases(args))
    Path(args.output).write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    valid = sum(case["metadata"]["validity"] == "valid" for case in cases)
    print(f"Generated {len(cases)} cases in {args.output} ({valid} valid, {len(cases) - valid} invalid)")


if __name__ == "__main__":
    main()
