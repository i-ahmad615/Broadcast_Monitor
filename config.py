"""Application configuration helpers."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"
DEFAULT_SMTP_PORT = "587"


def _get_env_value(name: str, default: str = "") -> str:
    """Return an environment variable value as a string."""
    return os.getenv(name, default)


def load_config() -> dict[str, str]:
    """Load environment variables from the .env file when present."""
    if ENV_PATH.exists():
        load_dotenv(ENV_PATH)

    return {
        "EMAIL_ADDRESS": _get_env_value("EMAIL_ADDRESS", ""),
        "EMAIL_PASSWORD": _get_env_value("EMAIL_PASSWORD", ""),
        "RECIPIENT_EMAIL": _get_env_value("RECIPIENT_EMAIL", ""),
        "SMTP_SERVER": _get_env_value("SMTP_SERVER", ""),
        "SMTP_PORT": _get_env_value("SMTP_PORT", DEFAULT_SMTP_PORT),
    }
