from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from modules.config_loader import ConfigError
from modules.validated_config import load_config


CONFIGS = [
    "baseline-smoke.yaml",
    "baseline-full.yaml",
    "baseline-large-body.yaml",
    "parser-stress-smoke.yaml",
    "parser-stress-full.yaml",
    "parser-stress-large-body.yaml",
    "parser-stress-deep-wide.yaml",
    "decompression-stress-smoke.yaml",
    "decompression-stress-highly-compressible.yaml",
    "decompression-stress-medium-compressible.yaml",
    "decompression-stress-incompressible.yaml",
]

STRUCTURAL_CONFIGS = [
    "baseline-smoke.yaml",
    "baseline-full.yaml",
    "baseline-large-body.yaml",
    "parser-stress-smoke.yaml",
    "parser-stress-full.yaml",
    "parser-stress-large-body.yaml",
    "parser-stress-deep-wide.yaml",
]


def test_all_repository_configs_validate():
    for name in CONFIGS:
        loaded = load_config(Path("configs") / name)
        assert loaded.profile in {"baseline", "parser-stress", "decompression-stress"}
        assert loaded.estimated_cases > 0
        assert loaded.estimated_cases <= loaded.safety["max_cases"]
        assert loaded.output_file.parent == Path("payloads")


def test_structural_configs_expose_payload_value():
    for name in STRUCTURAL_CONFIGS:
        path = Path("configs") / name
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        configured_payload = raw["generation"]["payload"]
        loaded = load_config(path)

        assert isinstance(configured_payload, str)
        assert configured_payload
        assert loaded.args.payload == configured_payload


def test_yaml_payload_value_is_mapped_to_generator_args(tmp_path: Path):
    config = yaml.safe_load(Path("configs/baseline-smoke.yaml").read_text(encoding="utf-8"))
    config["generation"]["payload"] = "custom-yaml-payload"
    path = tmp_path / "custom-payload.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    loaded = load_config(path)
    assert loaded.args.payload == "custom-yaml-payload"


def test_optimized_full_structural_configs_have_practical_scale():
    baseline = load_config("configs/baseline-full.yaml")
    parser = load_config("configs/parser-stress-full.yaml")
    assert 3000 <= baseline.estimated_cases <= 5000
    assert 3000 <= parser.estimated_cases <= 5000


def test_full_configs_bound_repeated_value_sizes():
    baseline = load_config("configs/baseline-full.yaml")
    parser = load_config("configs/parser-stress-full.yaml")
    assert baseline.args.sizes == [0, 256, 1024]
    assert parser.args.sizes == [1, 256, 1024]


def test_parser_full_bounds_structural_fanout():
    parser = load_config("configs/parser-stress-full.yaml")
    assert parser.args.depth == 32
    assert parser.args.width == 64
    assert parser.args.fields == 1024
    assert parser.args.field_name_lengths == [64, 256]
    assert parser.args.multipart_boundary_lengths == [70, 256]


def test_large_body_configs_keep_focused_64k_coverage():
    baseline = load_config("configs/baseline-large-body.yaml")
    parser = load_config("configs/parser-stress-large-body.yaml")
    assert baseline.args.sizes == [65536]
    assert parser.args.sizes == [65536]
    assert baseline.args.width == baseline.args.fields == 1
    assert parser.args.width == parser.args.fields == 1


def test_decompression_content_profiles_and_size_bounds():
    highly = load_config("configs/decompression-stress-highly-compressible.yaml")
    medium = load_config("configs/decompression-stress-medium-compressible.yaml")
    incompressible = load_config("configs/decompression-stress-incompressible.yaml")

    assert highly.args.content_profile == "highly-compressible"
    assert medium.args.content_profile == "medium-compressible"
    assert incompressible.args.content_profile == "incompressible"
    assert highly.args.decompressed_sizes == [1048576, 8388608, 67108864]
    assert medium.args.decompressed_sizes == [1048576, 8388608, 33554432]
    assert incompressible.args.decompressed_sizes == [1048576, 8388608]
    assert highly.args.algorithms == medium.args.algorithms == incompressible.args.algorithms
    assert highly.args.variants == medium.args.variants == incompressible.args.variants


def test_baseline_rejects_parser_only_option(tmp_path: Path):
    config = yaml.safe_load(Path("configs/baseline-smoke.yaml").read_text(encoding="utf-8"))
    config["generation"]["charset_modes"] = ["mismatch"]
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(ConfigError, match="charset_modes"):
        load_config(path)


def test_parser_config_maps_nested_charset_settings():
    loaded = load_config("configs/parser-stress-smoke.yaml")
    assert loaded.args.charsets == ["utf-8"]
    assert loaded.args.charset_modes == ["valid", "mismatch"]
    assert loaded.args.bom == [False]
    assert loaded.args.field_name_lengths == [16, 256]


def test_decompression_size_cannot_exceed_safety(tmp_path: Path):
    config = yaml.safe_load(Path("configs/decompression-stress-smoke.yaml").read_text(encoding="utf-8"))
    config["generation"]["decompressed_sizes"] = [16 * 1024 * 1024]
    path = tmp_path / "too-large.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(ConfigError, match="max_decompressed_size"):
        load_config(path)


def test_decompression_rejects_unknown_content_profile(tmp_path: Path):
    config = yaml.safe_load(Path("configs/decompression-stress-smoke.yaml").read_text(encoding="utf-8"))
    config["generation"].setdefault("content", {})["profile"] = "unknown"
    path = tmp_path / "invalid-profile.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(ConfigError, match="content.profile"):
        load_config(path)
