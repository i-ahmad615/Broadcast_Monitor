"""Utility helpers for the broadcast monitor."""

from __future__ import annotations


def ensure_directory(path: str) -> None:
    """Create a directory if it does not already exist."""
    from pathlib import Path

    Path(path).mkdir(parents=True, exist_ok=True)
