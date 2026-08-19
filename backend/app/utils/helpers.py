"""
Utility helpers shared across the SOAR application.

Provides:
  get_logger()  — Structured console + rotating-file logger factory.
  setup_logging() — One-shot root logging configuration called at startup.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler


_FORMATTER = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_ROOT_CONFIGURED = False
_BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _resolve_log_path(log_file: str) -> str:
    """Resolve relative log files against the backend root directory."""
    log_path = Path(log_file)
    if not log_path.is_absolute():
        log_path = (_BACKEND_ROOT / log_path).resolve()
    return str(log_path)


def setup_logging(log_level: str = "INFO", log_file: str = "soar.log",
                  max_bytes: int = 10_485_760, backup_count: int = 5) -> None:
    """
    Configure the root logger once at application startup.

    Installs two handlers:
      1. StreamHandler  → writes INFO+ to stdout (coloured by level).
      2. RotatingFileHandler → writes DEBUG+ to ``log_file``.

    Parameters
    ----------
    log_level    : Minimum level for the console handler (e.g. "INFO").
    log_file     : Path to the rotating log file.
    max_bytes    : Maximum size of a single log file before rotation.
    backup_count : How many old log files to keep.
    """
    global _ROOT_CONFIGURED
    if _ROOT_CONFIGURED:
        return

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # ── Console handler ────────────────────────────────────────────────────
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    console.setFormatter(_FORMATTER)
    root.addHandler(console)

    # ── Rotating file handler ──────────────────────────────────────────────
    try:
        file_handler = RotatingFileHandler(
            _resolve_log_path(log_file),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(_FORMATTER)
        root.addHandler(file_handler)
    except (OSError, PermissionError) as exc:
        root.warning("Could not open log file %r: %s — file logging disabled.", log_file, exc)

    # Suppress noisy third-party loggers
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    _ROOT_CONFIGURED = True
    root.info("Logging initialised | level=%s file=%s", log_level, log_file)


def get_logger(name: str = "soar") -> logging.Logger:
    """
    Return a named logger.

    The logger inherits its handlers from the root logger configured
    by setup_logging(). If setup_logging() has not been called yet,
    a minimal console handler is added on first use.

    Usage
    -----
    from app.utils.helpers import get_logger
    logger = get_logger(__name__)
    logger.info("Alert ingested | id=%s", alert_id)
    """
    logger = logging.getLogger(name)

    # Fallback: add a bare console handler if the root logger has none yet
    if not logging.getLogger().handlers and not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_FORMATTER)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger
