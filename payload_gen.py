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
ALL_VALUE_ENCODINGS = sorted({item for values in RECOMMENDED_VALUE_ENCODINGS.values() for item in values})


@dataclass(frozen=True)
class Document:
    body: str | bytes
    media_type: str
    structure: str
    validity: str
    metrics: dict[str, int | str | bool]


def repeat_to_length(pattern: str, size: int) -> str:
    if size <= 0:
        return ""
    return (pattern * ((size // max(1, len(pattern))) + 1))[:size]


def make_filler(size: int, kind: str, seed: int) -> str:
    if size <= 0:
        return ""
    if kind == "repeated":
        return "A" * size
    if kind == "unicode":
        return repeat_to_length("Привет世界🙂e\u0301\u200d", size)
    if kind == "random-ascii":
        rng = random.Random(seed + size)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        return "".join(rng.choice(alphabet) for _ in range(size))
    if kind == "numeric":
        return repeat_to_length("1234567890", size)
    if kind == "escape-json":
        return repeat_to_length('"\\/\n\r\t\b\f', size)
    if kind == "escape-xml":
        return repeat_to_length("<&>\"'", size)
    if kind == "escape-form":
        return repeat_to_length(" +%&=;/?:@", size)
    raise ValueError(f"Unsupported filler kind: {kind}")


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


def encode_document(body: str | bytes, declared_charset: str, bom: bool, charset_mode: str) -> tuple[bytes, str]:
    if isinstance(body, bytes):
        return body, "binary"
    if charset_mode == "valid":
        return encode_text(body, declared_charset, bom), declared_charset
    if charset_mode == "mismatch":
        actual = "utf-16le" if declared_charset.lower() != "utf-16le" else "utf-8"
        return encode_text(body, actual, bom=False), actual
    if charset_mode == "invalid-tail":
        return encode_text(body, declared_charset, bom) + b"\xff\xfe\xc0\xaf", declared_charset
    if charset_mode == "truncated-code-unit":
        encoded = encode_text(body, declared_charset, bom)
        return (encoded[:-1] if encoded else b"\xff"), declared_charset
    raise ValueError(f"Unsupported charset mode: {charset_mode}")


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
        value = bytearray(data)
        for index in range(max(0, len(value) - min(8, len(value))), len(value)):
            value[index] ^= 0xFF
        return bytes(value)
    if mode == "bitflip":
        value = bytearray(data)
        value[len(value) // 2] ^= 0x20
        return bytes(value)
    raise ValueError(f"Unsupported corruption mode: {mode}")


def value_encodings_for(fmt: str, structure: str, args: argparse.Namespace) -> list[str]:
    if structure == "invalid-percent":
        return ["plain"]
    if args.value_encodings:
        allowed = set(RECOMMENDED_VALUE_ENCODINGS[fmt])
        selected = [encoding for encoding in args.value_encodings if encoding in allowed]
        if not selected:
            raise ValueError(f"No requested value encodings are valid for format {fmt}")
        return selected
    if args.value_encoding_profile == "recommended":
        return list(RECOMMENDED_VALUE_ENCODINGS[fmt])
    return ["plain"]


def transform_value(value: str, encoding: str) -> str:
    if encoding in {"plain", "json-unicode-escape"}:
        return value
    if encoding == "base64":
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    if encoding in {"url", "double-url"}:
        return quote(value, safe="")
    raise ValueError(f"Unsupported value encoding: {encoding}")


def long_name(length: int, index: int = 0) -> str:
    suffix = f"_{index:08d}"
    if length <= len(suffix):
        return ("f" * max(0, length - len(str(index)))) + str(index)
    return ("field_" + "a" * length)[: length - len(suffix)] + suffix


def nested_json(value: Any, depth: int) -> Any:
    node = value
    for index in range(depth):
        node = {f"level_{index}": node}
    return node


def build_json(value: str, structure: str, depth: int, width: int, fields: int, name_length: int, ensure_ascii: bool) -> Document:
    dumps = lambda obj: json.dumps(obj, ensure_ascii=ensure_ascii, separators=(",", ":"))
    if structure == "single":
        obj: Any = {"input": value}; metrics = {"depth": 1, "width": 1, "fields": 1}
    elif structure == "deep":
        obj = nested_json(value, depth); metrics = {"depth": depth, "width": 1, "fields": depth}
    elif structure == "wide":
        obj = {f"field_{i:06d}": value for i in range(width)}; metrics = {"depth": 1, "width": width, "fields": width}
    elif structure == "array":
        obj = [value for _ in range(width)]; metrics = {"depth": 1, "width": width, "fields": width}
    elif structure == "many-fields":
        obj = {f"k{i}": i for i in range(fields)}; obj["input"] = value; metrics = {"depth": 1, "width": fields + 1, "fields": fields + 1}
    elif structure == "duplicate-keys":
        pairs = ",".join(f'"dup":{dumps(value)}' for _ in range(fields))
        return Document("{" + pairs + "}", "application/json", structure, "valid", {"depth": 1, "width": fields, "fields": fields})
    elif structure == "deep-wide":
        node: Any = value
        for level in range(depth):
            siblings = {f"s{level}_{i}": value for i in range(max(0, width - 1))}
            siblings[f"next_{level}"] = node
            node = siblings
        obj = node; metrics = {"depth": depth, "width": width, "fields": depth * width}
    elif structure == "array-objects":
        obj = [{"index": i, "value": value} for i in range(width)]; metrics = {"depth": 2, "width": width, "fields": width * 2}
    elif structure == "array-mixed":
        templates: list[Any] = [value, None, True, 0, {"value": value}, [value]]
        obj = [templates[i % len(templates)] for i in range(width)]; metrics = {"depth": 2, "width": width, "fields": width}
    elif structure == "long-field-name":
        obj = {long_name(name_length): value}; metrics = {"depth": 1, "width": 1, "fields": 1, "field_name_length": name_length}
    elif structure == "many-long-field-names":
        obj = {long_name(name_length, i): value for i in range(fields)}; metrics = {"depth": 1, "width": fields, "fields": fields, "field_name_length": name_length}
    elif structure == "escape-heavy":
        obj = {"input": repeat_to_length('"\\/\n\r\t\b\f\u0041', max(1, len(value)))}; metrics = {"depth": 1, "width": 1, "fields": 1, "escape_heavy": True}
    elif structure == "truncated":
        valid = dumps({"input": value}); return Document(valid[:-1], "application/json", structure, "invalid", {"depth": 1, "width": 1, "fields": 1})
    elif structure == "trailing-garbage":
        valid = dumps({"input": value}); return Document(valid + " trailing", "application/json", structure, "invalid", {"depth": 1, "width": 1, "fields": 1})
    else:
        raise ValueError(f"Unsupported JSON structure: {structure}")
    return Document(dumps(obj), "application/json", structure, "valid", metrics)


def build_form(value: str, structure: str, fields: int, name_length: int) -> Document:
    validity = "valid"
    if structure == "single": pairs = [("input", value)]
    elif structure == "many-fields": pairs = [(f"k{i}", str(i)) for i in range(fields)] + [("input", value)]
    elif structure == "repeated-keys": pairs = [("input", value) for _ in range(fields)]
    elif structure == "empty-pairs": return Document("&".join(["=", "a=", "=b", "input=" + value]), "application/x-www-form-urlencoded", structure, validity, {"fields": 4, "depth": 1, "width": 4})
    elif structure == "invalid-percent": return Document("input=%E2%82&bad=%ZZ&tail=%", "application/x-www-form-urlencoded", structure, "invalid", {"fields": 3, "depth": 1, "width": 3})
    elif structure == "long-field-name": pairs = [(long_name(name_length), value)]
    elif structure == "many-long-field-names": pairs = [(long_name(name_length, i), value) for i in range(fields)]
    elif structure == "mixed-types": pairs = [("input", value), ("input[]", value), ("input[key]", value), ("input", "scalar")]
    elif structure == "escape-heavy": pairs = [("input", repeat_to_length(" +%&=;/?:@", max(1, len(value))))]
    else: raise ValueError(f"Unsupported form structure: {structure}")
    metrics: dict[str, int | str | bool] = {"fields": len(pairs), "depth": 1, "width": len(pairs)}
    if "long-field" in structure: metrics["field_name_length"] = name_length
    return Document(urlencode(pairs), "application/x-www-form-urlencoded", structure, validity, metrics)


def build_xml(value: str, structure: str, depth: int, width: int, name_length: int) -> Document:
    safe = xml_escape(value, {'"': "&quot;", "'": "&apos;"}); validity = "valid"
    if structure == "single": body = f'<?xml version="1.0"?><root><input>{safe}</input></root>'; metrics = {"depth": 2, "width": 1, "fields": 1}
    elif structure == "deep":
        opening = "".join(f"<level{i}>" for i in range(depth)); closing = "".join(f"</level{i}>" for i in reversed(range(depth)))
        body = f'<?xml version="1.0"?><root>{opening}{safe}{closing}</root>'; metrics = {"depth": depth + 1, "width": 1, "fields": depth}
    elif structure == "wide": body = f'<?xml version="1.0"?><root>{"".join(f"<item id=\"{i}\">{safe}</item>" for i in range(width))}</root>'; metrics = {"depth": 2, "width": width, "fields": width}
    elif structure == "attributes":
        attrs = " ".join(f'a{i}="{i}"' for i in range(width)); body = f'<?xml version="1.0"?><root {attrs}><input>{safe}</input></root>'; metrics = {"depth": 2, "width": width, "fields": width}
    elif structure == "deep-wide":
        opening: list[str] = []; closing: list[str] = []
        for level in range(depth):
            opening.append(f"<level{level}>"); opening.extend(f"<sibling>{safe}</sibling>" for _ in range(max(0, width - 1))); closing.insert(0, f"</level{level}>")
        body = '<?xml version="1.0"?><root>' + "".join(opening) + safe + "".join(closing) + "</root>"; metrics = {"depth": depth + 1, "width": width, "fields": depth * width}
    elif structure == "long-element-name":
        name = "e" * max(1, name_length); body = f'<?xml version="1.0"?><root><{name}>{safe}</{name}></root>'; metrics = {"depth": 2, "width": 1, "fields": 1, "field_name_length": name_length}
    elif structure == "long-attribute-name":
        name = "a" * max(1, name_length); body = f'<?xml version="1.0"?><root {name}="1"><input>{safe}</input></root>'; metrics = {"depth": 2, "width": 1, "fields": 1, "field_name_length": name_length}
    elif structure == "escape-heavy":
        escaped = "&amp;&lt;&gt;&quot;&apos;&#65;&#x41;" * max(1, len(value) // 8); body = f'<?xml version="1.0"?><root><input>{escaped}</input></root>'; metrics = {"depth": 2, "width": 1, "fields": 1, "escape_heavy": True}
    elif structure == "truncated": body = f'<?xml version="1.0"?><root><input>{safe}</input>'; validity = "invalid"; metrics = {"depth": 2, "width": 1, "fields": 1}
    else: raise ValueError(f"Unsupported XML structure: {structure}")
    return Document(body, "application/xml", structure, validity, metrics)


def multipart_body(parts: list[tuple[str, str | None, str]], boundary: str, line: str = "\r\n", close: bool = True) -> str:
    output: list[str] = []
    for name, filename, content in parts:
        output.append(f"--{boundary}"); disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None: disposition += f'; filename="{filename}"'
        output.extend([disposition, "", content])
    if close: output.extend([f"--{boundary}--", ""])
    return line.join(output)


def build_multipart(value: str, structure: str, fields: int, boundary: str, name_length: int) -> Document:
    validity = "valid"; line = "\r\n"
    if structure == "single": parts = [("input", None, value)]
    elif structure in {"many-fields", "many-short-parts"}: parts = [(f"field_{i}", None, value if structure == "many-fields" else str(i % 10)) for i in range(fields)]
    elif structure == "empty-parts": parts = [(f"field_{i}", None, "") for i in range(fields)]
    elif structure == "long-name": parts = [(long_name(name_length), None, value)]
    elif structure == "long-filename": parts = [("upload", "f" * max(1, name_length), value)]
    elif structure == "long-boundary": parts = [("input", None, value)]
    elif structure == "boundary-collision": parts = [("input", None, value + f"\r\n--{boundary[:-1]}X\r\n" + value)]
    elif structure == "missing-close":
        parts = [(f"field_{i}", None, value) for i in range(fields)]; validity = "invalid"
        return Document(multipart_body(parts, boundary, close=False), f"multipart/form-data; boundary={boundary}", structure, validity, {"fields": fields, "depth": 1, "width": fields})
    elif structure == "lf-only": parts = [(f"field_{i}", None, value) for i in range(fields)]; line = "\n"
    else: raise ValueError(f"Unsupported multipart structure: {structure}")
    metrics: dict[str, int | str | bool] = {"fields": len(parts), "depth": 1, "width": len(parts), "boundary_length": len(boundary)}
    if structure in {"long-name", "long-filename"}: metrics["field_name_length"] = name_length
    return Document(multipart_body(parts, boundary, line=line), f"multipart/form-data; boundary={boundary}", structure, validity, metrics)


def build_document(fmt: str, value: str, value_encoding: str, structure: str, depth: int, width: int, fields: int, boundary: str, name_length: int) -> Document:
    if fmt == "json": return build_json(value, structure, depth, width, fields, name_length, ensure_ascii=value_encoding == "json-unicode-escape")
    if fmt == "form": return build_form(value, structure, fields, name_length)
    if fmt == "xml": return build_xml(value, structure, depth, width, name_length)
    if fmt == "multipart": return build_multipart(value, structure, fields, boundary, name_length)
    if fmt == "text":
        text = repeat_to_length('"\\/<>&%\n\r\t', max(1, len(value))) if structure == "escape-heavy" else value
        return Document(text, "text/plain", structure, "valid", {"depth": 1, "width": 1, "fields": 1, "escape_heavy": structure == "escape-heavy"})
    if fmt == "octet-stream": return Document(value.encode("utf-8"), "application/octet-stream", "single", "valid", {"depth": 1, "width": 1, "fields": 1})
    raise ValueError(f"Unsupported format: {fmt}")


def structures_for(fmt: str, args: argparse.Namespace) -> list[str]:
    return BASE_STRUCTURES[fmt] + (PHASE1_STRUCTURES[fmt] if args.stress_profile == "phase1" else [])


def name_lengths_for(structure: str, args: argparse.Namespace) -> list[int]:
    return args.field_name_lengths if structure in {"long-field-name", "many-long-field-names", "long-element-name", "long-attribute-name", "long-name", "long-filename"} else [0]


def boundary_lengths_for(structure: str, args: argparse.Namespace) -> list[int]:
    return args.multipart_boundary_lengths if structure == "long-boundary" else [0]


def iter_cases(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    case_number = 0; compressions = list(args.compressions)
    if brotli is None and "br" in compressions:
        compressions.remove("br"); print("Warning: brotli is unavailable; br cases are skipped.")
    for fmt in args.formats:
        for structure in structures_for(fmt, args):
            for name_length in name_lengths_for(structure, args):
                for requested_boundary_length in boundary_lengths_for(structure, args):
                    for charset in args.charsets:
                        if fmt == "octet-stream" and charset != "utf-8": continue
                        for charset_mode in args.charset_modes:
                            if fmt == "octet-stream" and charset_mode != "valid": continue
                            for bom in args.bom:
                                if bom and charset not in {"utf-8", "utf-16le", "utf-16be", "utf-32le", "utf-32be"}: continue
                                for filler_kind in args.filler_kinds:
                                    for requested_size in args.sizes:
                                        logical_value = make_filler(requested_size, filler_kind, args.seed) + args.payload
                                        default_boundary = f"----WAFPayloadBoundary{args.seed:08d}"
                                        boundary = ("B" * max(1, requested_boundary_length)) if requested_boundary_length else default_boundary
                                        for value_encoding in value_encodings_for(fmt, structure, args):
                                            encoded_value = transform_value(logical_value, value_encoding)
                                            document = build_document(fmt, encoded_value, value_encoding, structure, args.depth, args.width, args.fields, boundary, name_length)
                                            serialized, actual_charset = encode_document(document.body, charset, bom, charset_mode)
                                            for compression in compressions:
                                                compressed = compress_body(serialized, compression); corruption_modes = ["valid"]
                                                if compression != "none" and args.include_corrupt_compression: corruption_modes += ["truncated", "bad-tail", "bitflip"]
                                                for corruption in corruption_modes:
                                                    wire_body = corrupt_compressed(compressed, corruption); case_number += 1
                                                    case_id = f"case-{case_number:06d}-{fmt}-{structure}-{value_encoding}-{charset}-{charset_mode}-{compression}-{corruption}"
                                                    content_type = document.media_type if fmt in {"octet-stream", "multipart"} else f"{document.media_type}; charset={charset}"
                                                    headers = {"Content-Type": content_type, "X-WAF-Test-Case-ID": case_id}
                                                    if compression != "none": headers["Content-Encoding"] = "deflate" if compression == "raw-deflate" else compression
                                                    validity = "invalid-compression" if corruption != "valid" else "invalid-charset" if charset_mode != "valid" else document.validity
                                                    metadata: dict[str, Any] = {
                                                        "format": fmt, "structure": document.structure, "validity": validity, "value_encoding": value_encoding,
                                                        "charset": charset, "actual_charset": actual_charset, "charset_mode": charset_mode, "bom": bom,
                                                        "filler_kind": filler_kind, "requested_filler_chars": requested_size,
                                                        "encoded_value_utf8_size": len(encoded_value.encode("utf-8")), "compression": compression,
                                                        "compression_corruption": corruption, "seed": args.seed, "stress_profile": args.stress_profile, **document.metrics,
                                                    }
                                                    yield {
                                                        "id": case_id, "method": "POST", "path": args.path, "headers": headers,
                                                        "body_base64": base64.b64encode(wire_body).decode("ascii"), "sha256": hashlib.sha256(wire_body).hexdigest(),
                                                        "logical_size": len(logical_value.encode("utf-8")), "serialized_size": len(serialized), "wire_body_size": len(wire_body),
                                                        "expansion_ratio": round(len(serialized) / max(1, len(wire_body)), 4), "metadata": metadata,
                                                    }


def parse_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate byte-exact WAF request cases")
    parser.add_argument("--output", default="payloads.json", help="Output JSON manifest")
    parser.add_argument("--payload", default="normal-client-value", help="Suffix included in every logical value")
    parser.add_argument("--path", default="/endpoint", help="Request path stored in every case")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--stress-profile", choices=["baseline", "phase1"], default="baseline", help="Enable phase-1 parser and allocation stress structures")
    parser.add_argument("--size-profile", choices=["default", "boundaries"], default="default", help="Use ordinary sizes or allocation/limit boundary sizes")
    parser.add_argument("--sizes", type=int, nargs="+", help="Logical filler sizes; overrides --size-profile")
    parser.add_argument("--formats", nargs="+", choices=list(STRUCTURES), default=list(STRUCTURES))
    parser.add_argument("--charsets", nargs="+", default=["utf-8", "utf-16le", "utf-16be"])
    parser.add_argument("--charset-modes", nargs="+", choices=["valid", "mismatch", "invalid-tail", "truncated-code-unit"], default=["valid"])
    parser.add_argument("--compressions", nargs="+", choices=["none", "gzip", "deflate", "raw-deflate", "br"], default=["none", "gzip", "deflate"])
    parser.add_argument("--filler-kinds", nargs="+", choices=["repeated", "random-ascii", "unicode", "numeric", "escape-json", "escape-xml", "escape-form"], default=["repeated", "random-ascii", "unicode"])
    parser.add_argument("--bom", nargs="+", type=parse_bool, default=[False, True], metavar="BOOL")
    parser.add_argument("--value-encoding-profile", choices=["plain", "recommended"], default="plain")
    parser.add_argument("--value-encodings", nargs="+", choices=ALL_VALUE_ENCODINGS)
    parser.add_argument("--depth", type=int, default=64)
    parser.add_argument("--width", type=int, default=256)
    parser.add_argument("--fields", type=int, default=512)
    parser.add_argument("--field-name-lengths", type=int, nargs="+", default=[16, 256, 1024, 8192])
    parser.add_argument("--multipart-boundary-lengths", type=int, nargs="+", default=[70, 256, 1024, 8192])
    parser.add_argument("--include-corrupt-compression", action="store_true")
    args = parser.parse_args()
    if args.sizes is None: args.sizes = BOUNDARY_SIZES if args.size_profile == "boundaries" else [0, 100, 1000, 10000]
    for name, values in (("sizes", args.sizes), ("field-name-lengths", args.field_name_lengths), ("multipart-boundary-lengths", args.multipart_boundary_lengths)):
        if any(value < 0 for value in values): parser.error(f"--{name} values must be non-negative")
    return args


def main() -> None:
    args = parse_args(); cases = list(iter_cases(args)); output = Path(args.output)
    output.write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    valid = sum(case["metadata"]["validity"] == "valid" for case in cases)
    print(f"Generated {len(cases)} cases in {output} ({valid} valid, {len(cases) - valid} invalid)")


if __name__ == "__main__":
    main()
