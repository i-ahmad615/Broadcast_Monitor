"""Logging helpers for the broadcast monitor."""

from __future__ import annotations

import logging


def setup_logger() -> logging.Logger:
    """Create and configure a logger instance."""
    logger = logging.getLogger("broadcast_monitor")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(handler)
    return logger
