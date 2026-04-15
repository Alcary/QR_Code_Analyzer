"""
Logging configuration loader.

Reads logging.yaml from the server root and creates the logs/ directory
automatically. Falls back to basicConfig if the file is missing.
"""

import logging
import logging.config
import logging.handlers
import os
from pathlib import Path

import yaml


def setup_logging() -> None:
    """
    Configure logging from logging.yaml.

    Falls back to a sensible basicConfig if the file is missing or
    cannot be parsed, so the server always starts even if the config
    file is accidentally deleted.
    """
    config_path = _find_config()

    # Ensure the logs/ directory exists before the file handler tries to open it
    logs_dir = _server_root() / "logs"
    logs_dir.mkdir(exist_ok=True)

    if config_path and config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)

            # Patch the log file path to be absolute so it works regardless
            # of the working directory the server is launched from.
            try:
                config["handlers"]["file"]["filename"] = str(logs_dir / "server.log")
            except (KeyError, TypeError):
                pass

            logging.config.dictConfig(config)
            logging.getLogger(__name__).info(
                "Logging configured from %s — writing to %s",
                config_path,
                logs_dir / "server.log",
            )
            return
        except Exception as e:
            # Don't crash the server over a logging misconfiguration.
            # Fall through to basicConfig below and report what went wrong.
            logging.basicConfig(level=logging.INFO)
            logging.getLogger(__name__).warning(
                "Failed to load logging config from %s (%s) — using basicConfig fallback",
                config_path,
                e,
            )
            return

    # Fallback: no config file found
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.getLogger(__name__).warning(
        "logging.yaml not found — using basicConfig fallback"
    )


def _server_root() -> Path:
    """Return the qr-security-server/ root directory."""
    return Path(__file__).resolve().parent.parent.parent


def _find_config() -> Path | None:
    """Look for logging.yaml next to the server root."""
    candidate = _server_root() / "logging.yaml"
    return candidate if candidate.exists() else None
