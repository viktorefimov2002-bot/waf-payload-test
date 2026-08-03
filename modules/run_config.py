#!/usr/bin/env python3
"""Strict YAML configuration loader for run_suite.py."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

MODES = {"fast", "informative", "high-rps"}
ROOT_KEYS = {"version", "name", "target", "input", "execution", "selection", "output"}
TARGET_KEYS = {"url"}
INPUT_KEYS = {"payload_file", "k6_script"}
EXECUTION_COMMON = {
    "mode", "batch_size", "rps", "duration", "cooldown", "graceful_stop",
    "threshold_mode", "batch_max_duration",
}
EXECUTION_HIGH_RPS = EXECUTION_COMMON | {"preallocated_vus", "max_vus"}
SELECTION_KEYS = {
    "start_index", "limit", "case_id", "formats", "structures", "value_encodings",
    "charsets", "compressions", "validities", "list_only",
}
OUTPUT_KEYS = {"results_dir", "print_request", "terminate_timeout"}


class RunConfigError(ValueError):
    pass


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RunConfigError(f"{path} must be a mapping")
    return value


def _forbid_extra(value: dict[str, Any], allowed: set[str], path: str) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        raise RunConfigError(f"unsupported option(s) for {path}: {', '.join(extra)}")


def _string(value: Any, path: str, *, required: bool = False, default: str | None = None) -> str | None:
    if value is None:
        if required:
            raise RunConfigError(f"{path} is required")
        return default
    if not isinstance(value, str) or not value.strip():
        raise RunConfigError(f"{path} must be a non-empty string")
    return value


def _int(value: Any, path: str, *, minimum: int, default: int | None = None) -> int | None:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise RunConfigError(f"{path} must be an integer >= {minimum}")
    return value


def _number(value: Any, path: str, *, minimum: float, default: float) -> float:
    if value is None:
        return default
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < minimum:
        raise RunConfigError(f"{path} must be a number >= {minimum}")
    return float(value)


def _strings(value: Any, path: str) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise RunConfigError(f"{path} must be a non-empty list of strings")
    return value


def load_run_config(path: str | Path, *, target_override: str | None = None, payload_override: str | None = None) -> argparse.Namespace:
    config_path = Path(path)
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RunConfigError(f"cannot read run config: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RunConfigError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RunConfigError("root must be a mapping")
    _forbid_extra(data, ROOT_KEYS, "root")
    if data.get("version") != 1:
        raise RunConfigError("version must be 1")

    target = _mapping(data.get("target"), "target")
    input_cfg = _mapping(data.get("input"), "input")
    execution = _mapping(data.get("execution"), "execution")
    selection = _mapping(data.get("selection"), "selection")
    output = _mapping(data.get("output"), "output")
    _forbid_extra(target, TARGET_KEYS, "target")
    _forbid_extra(input_cfg, INPUT_KEYS, "input")
    _forbid_extra(selection, SELECTION_KEYS, "selection")
    _forbid_extra(output, OUTPUT_KEYS, "output")

    mode = _string(execution.get("mode"), "execution.mode", required=True)
    if mode not in MODES:
        raise RunConfigError(f"execution.mode must be one of: {', '.join(sorted(MODES))}")
    _forbid_extra(execution, EXECUTION_HIGH_RPS if mode == "high-rps" else EXECUTION_COMMON, f'execution for mode "{mode}"')

    threshold_mode = _string(execution.get("threshold_mode"), "execution.threshold_mode", default="disabled")
    if threshold_mode not in {"disabled", "strict"}:
        raise RunConfigError("execution.threshold_mode must be disabled or strict")
    print_request = _string(output.get("print_request"), "output.print_request")
    if print_request is not None and print_request not in {"none", "headers", "full"}:
        raise RunConfigError("output.print_request must be none, headers, or full")
    validities = _strings(selection.get("validities"), "selection.validities")
    if validities and any(item not in {"valid", "invalid", "invalid-compression", "invalid-charset"} for item in validities):
        raise RunConfigError("selection.validities contains an unsupported value")

    default_batch = 1 if mode == "informative" else 10 if mode == "high-rps" else 25
    namespace = argparse.Namespace(
        target=target_override or _string(target.get("url"), "target.url", required=True),
        payload_file=payload_override or _string(input_cfg.get("payload_file"), "input.payload_file", required=True),
        k6_script=_string(input_cfg.get("k6_script"), "input.k6_script", default="k6_run_payloads.js"),
        mode=mode,
        batch_size=_int(execution.get("batch_size"), "execution.batch_size", minimum=1, default=default_batch),
        rps=_int(execution.get("rps"), "execution.rps", minimum=1, default=10),
        duration=_string(execution.get("duration"), "execution.duration", default="30s"),
        cooldown=_number(execution.get("cooldown"), "execution.cooldown", minimum=0, default=5.0),
        graceful_stop=_string(execution.get("graceful_stop"), "execution.graceful_stop", default="1s"),
        threshold_mode=threshold_mode,
        batch_max_duration=_string(execution.get("batch_max_duration"), "execution.batch_max_duration", default="24h"),
        preallocated_vus=_int(execution.get("preallocated_vus"), "execution.preallocated_vus", minimum=1),
        max_vus=_int(execution.get("max_vus"), "execution.max_vus", minimum=1),
        start_index=_int(selection.get("start_index"), "selection.start_index", minimum=0, default=0),
        limit=_int(selection.get("limit"), "selection.limit", minimum=1),
        case_id=_string(selection.get("case_id"), "selection.case_id"),
        formats=_strings(selection.get("formats"), "selection.formats"),
        structures=_strings(selection.get("structures"), "selection.structures"),
        value_encodings=_strings(selection.get("value_encodings"), "selection.value_encodings"),
        charsets=_strings(selection.get("charsets"), "selection.charsets"),
        compressions=_strings(selection.get("compressions"), "selection.compressions"),
        validities=validities,
        list=bool(selection.get("list_only", False)),
        print_request=print_request,
        results_dir=_string(output.get("results_dir"), "output.results_dir", default="results"),
        terminate_timeout=_number(output.get("terminate_timeout"), "output.terminate_timeout", minimum=0.1, default=10.0),
        run_config_file=str(config_path),
        run_config_name=_string(data.get("name"), "name", default=config_path.stem),
    )
    if mode != "high-rps" and (namespace.preallocated_vus is not None or namespace.max_vus is not None):
        raise RunConfigError("preallocated_vus and max_vus are allowed only for high-rps mode")
    if namespace.preallocated_vus and namespace.max_vus and namespace.preallocated_vus > namespace.max_vus:
        raise RunConfigError("execution.preallocated_vus must not exceed execution.max_vus")
    return namespace
