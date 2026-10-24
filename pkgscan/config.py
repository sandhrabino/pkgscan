from __future__ import annotations

import os
from pathlib import Path

import yaml

PKG_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = PKG_DIR / "default_config.yaml"
RULES_DIR = PKG_DIR / "rules"
DATA_DIR = PKG_DIR / "data"


def _merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path: str | os.PathLike | None = None) -> dict:
    cfg = yaml.safe_load(DEFAULT_CONFIG.read_text())
    path = path or os.environ.get("PKGSCAN_CONFIG")
    if path:
        _merge(cfg, yaml.safe_load(Path(path).read_text()) or {})
    return cfg


def read_list(name: str) -> list[str]:
    lines = (DATA_DIR / name).read_text().splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]
