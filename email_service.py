"""Email notification service for the broadcast monitor."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from config import load_config

logger = logging.getLogger("broadcast_monitor")
EMAIL_SUBJECT = "Broadcast Packet Detected"
SMTP_TIMEOUT_SECONDS = 10


def send_email_alert(payload: dict[str, str]) -> None:
    """Send an email alert for a detected broadcast packet."""
    try:
        config = load_config()
        address = config.get("EMAIL_ADDRESS", "")
        password = config.get("EMAIL_PASSWORD", "")
        recipient = config.get("RECIPIENT_EMAIL", "")
        smtp_server = config.get("SMTP_SERVER", "")
        smtp_port = int(config.get("SMTP_PORT", "587") or "587")

        if not all([address, password, recipient, smtp_server]):
            logger.warning("Email configuration is incomplete; skipping email alert.")
            return

        message = EmailMessage()
        message["Subject"] = EMAIL_SUBJECT
        message["From"] = address
        message["To"] = recipient
        message.set_content(
            "Broadcast Packet Alert\n\n"
            "Timestamp:\n"
            f"{payload.get('timestamp', '')}\n\n"
            "Source IP:\n"
            f"{payload.get('source_ip', '')}\n\n"
            "Source MAC:\n"
            f"{payload.get('source_mac', '')}\n\n"
            "Destination MAC:\n"
            f"{payload.get('destination_mac', '')}\n\n"
            "Protocol:\n"
            f"{payload.get('protocol', '')}\n\n"
            "Generated automatically by the Broadcast Traffic Monitoring System."
        )

        with smtplib.SMTP(smtp_server, smtp_port, timeout=SMTP_TIMEOUT_SECONDS) as server:
            server.starttls()
            server.login(address, password)
            server.send_message(message)

        logger.info("Email notification sent successfully.")
    except Exception as exc:  # pragma: no cover - depends on runtime environment
        logger.exception("Email notification failed: %s", exc)
