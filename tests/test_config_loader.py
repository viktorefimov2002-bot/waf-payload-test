from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from modules.config_loader import ConfigError
from modules.validated_config import load_config


CONFIGS = [
    "baseline-smoke.yaml",
    "baseline-full.yaml",
    "parser-stress-smoke.yaml",
    "parser-stress-full.yaml",
    "decompression-stress-smoke.yaml",
    "decompression-stress-full.yaml",
]


def test_all_repository_configs_validate():
    for name in CONFIGS:
        loaded = load_config(Path("configs") / name)
        assert loaded.profile in {"baseline", "parser-stress", "decompression-stress"}
        assert loaded.estimated_cases > 0
        assert loaded.estimated_cases <= loaded.safety["max_cases"]


def test_optimized_full_structural_configs_have_practical_scale():
    baseline = load_config("configs/baseline-full.yaml")
    parser = load_config("configs/parser-stress-full.yaml")
    assert 3000 <= baseline.estimated_cases <= 5000
    assert 3000 <= parser.estimated_cases <= 5000


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
