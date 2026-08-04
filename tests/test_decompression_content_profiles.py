from modules.decompression_profile import build_serialized_body, compress_once


def test_content_profiles_are_deterministic_and_size_exact():
    for profile in ("highly-compressible", "medium-compressible", "incompressible"):
        first = build_serialized_body("json", 65536, profile, "A", 42)
        second = build_serialized_body("json", 65536, profile, "A", 42)
        assert first == second
        assert len(first) == 65536
        assert first.startswith(b'{"data":"')
        assert first.endswith(b'"}')


def test_compression_ratio_ordering():
    size = 1024 * 1024
    highly = build_serialized_body("text", size, "highly-compressible", "A", 42)
    medium = build_serialized_body("text", size, "medium-compressible", "A", 42)
    incompressible = build_serialized_body("text", size, "incompressible", "A", 42)

    highly_wire = compress_once(highly, "gzip")
    medium_wire = compress_once(medium, "gzip")
    incompressible_wire = compress_once(incompressible, "gzip")

    assert len(highly_wire) < len(medium_wire) < len(incompressible_wire)
    assert len(incompressible_wire) > size // 2
