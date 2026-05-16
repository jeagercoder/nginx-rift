"""Logging configuration for the scanner."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
SCANNER_ROOT = "scanner"


def setup_logging(
    *,
    quiet: bool = False,
    verbose: bool = False,
    log_file: str | None = None,
) -> None:
    root = logging.getLogger(SCANNER_ROOT)
    root.handlers.clear()
    root.propagate = False
    root.setLevel(logging.DEBUG)

    console = logging.StreamHandler(sys.stdout)
    if quiet:
        console.setLevel(logging.WARNING)
    elif verbose:
        console.setLevel(logging.DEBUG)
    else:
        console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    root.addHandler(console)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        root.addHandler(file_handler)

    if quiet:
        logging.getLogger(f"{SCANNER_ROOT}.engine").setLevel(logging.WARNING)
    elif verbose:
        logging.getLogger(f"{SCANNER_ROOT}.engine").setLevel(logging.DEBUG)
    else:
        logging.getLogger(f"{SCANNER_ROOT}.engine").setLevel(logging.INFO)


def get_logger(name: str) -> logging.Logger:
    if name.startswith(SCANNER_ROOT):
        return logging.getLogger(name)
    return logging.getLogger(f"{SCANNER_ROOT}.{name}")
