"""Configuration loader and validation for the HIPAA Compliance Engine."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from engine.exceptions import ConfigurationError

BASE_DIR = Path(__file__).resolve().parent.parent


def load_config(config_path: str | None = None, demo: bool = False) -> dict[str, Any]:
    """Load and validate engine configuration.

    Args:
        config_path: Path to config file. If None, uses default.
        demo: If True, loads demo configuration.

    Returns:
        Validated configuration dictionary.
    """
    if config_path is None:
        filename = "config_demo.yaml" if demo else "config.yaml"
        config_path = str(BASE_DIR / filename)

    path = Path(config_path)
    if not path.exists():
        raise ConfigurationError(f"Configuration file not found: {config_path}")

    with open(path, "r") as f:
        config = yaml.safe_load(f)

    if config is None:
        raise ConfigurationError(f"Empty configuration file: {config_path}")

    _validate_config(config)
    config["_base_dir"] = str(BASE_DIR)
    config["_demo"] = demo

    return config


def _validate_config(config: dict) -> None:
    """Validate required configuration sections exist."""
    required_sections = ["organization"]
    for section in required_sections:
        if section not in config:
            raise ConfigurationError(f"Missing required config section: {section}")

    org = config["organization"]
    if "name" not in org:
        raise ConfigurationError("Organization name is required")


def get_data_dir() -> Path:
    """Get the data directory path, creating it if needed."""
    data_dir = BASE_DIR / "data"
    data_dir.mkdir(exist_ok=True)
    return data_dir


def get_output_dir() -> Path:
    """Get the output directory path, creating it if needed."""
    output_dir = BASE_DIR / "output"
    output_dir.mkdir(exist_ok=True)
    return output_dir


def get_demo_data_dir() -> Path:
    """Get the demo sample data directory."""
    return BASE_DIR / "demo" / "sample_data"
