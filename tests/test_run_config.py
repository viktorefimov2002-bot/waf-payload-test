from pathlib import Path

import pytest
import yaml

from modules.run_config import RunConfigError, load_run_config


RUN_CONFIGS = [
    "baseline-fast.yaml",
    "parser-informative.yaml",
    "decompression-informative.yaml",
    "high-rps-recheck.yaml",
]


def test_repository_run_configs_validate():
    for name in RUN_CONFIGS:
        args = load_run_config(Path("run-configs") / name)
        assert args.mode in {"fast", "informative", "high-rps"}
        assert args.payload_file.startswith("payloads/")
        assert args.results_dir == "results"


def test_fast_mode_rejects_high_rps_only_options(tmp_path: Path):
    config = yaml.safe_load(Path("run-configs/baseline-fast.yaml").read_text(encoding="utf-8"))
    config["execution"]["preallocated_vus"] = 10
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(RunConfigError, match="preallocated_vus"):
        load_run_config(path)


def test_high_rps_vus_order_is_validated(tmp_path: Path):
    config = yaml.safe_load(Path("run-configs/high-rps-recheck.yaml").read_text(encoding="utf-8"))
    config["execution"]["preallocated_vus"] = 300
    config["execution"]["max_vus"] = 200
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    with pytest.raises(RunConfigError, match="must not exceed"):
        load_run_config(path)


def test_cli_overrides_target():
    args = load_run_config("run-configs/baseline-fast.yaml", target_override="https://127.0.0.1")
    assert args.target == "https://127.0.0.1"
