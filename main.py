"""Entry point for the broadcast monitoring application."""

import csv
from pathlib import Path

from config import load_config
from detector import extract_packet_details, is_broadcast_packet
from email_service import send_email_alert
from logger import setup_logger
from packet_capture import (
    PacketCaptureError,
    capture_packets,
    get_available_interfaces,
    resolve_interface_name,
    resolve_preferred_tshark_interface,
)
from utils.helpers import ensure_directory

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "broadcasts.csv"
CSV_FIELDS = ["Timestamp", "Source IP", "Source MAC", "Destination MAC", "Protocol"]
logger = setup_logger()


def process_packet(packet: object) -> None:
    """Run the full broadcast monitoring workflow for a packet."""
    try:
        if not is_broadcast_packet(packet):
            return

        details = extract_packet_details(packet)
        ensure_directory(str(LOG_DIR))
        file_exists = LOG_FILE.exists()

        with LOG_FILE.open("a", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(
                {
                    "Timestamp": details["timestamp"],
                    "Source IP": details["source_ip"],
                    "Source MAC": details["source_mac"],
                    "Destination MAC": details["destination_mac"],
                    "Protocol": details["protocol"],
                }
            )

        try:
            send_email_alert(details)
        except Exception as exc:  # pragma: no cover - depends on runtime environment
            logger.exception("Email alert failed: %s", exc)

        logger.info("Broadcast packet detected and logged")
    except Exception as exc:  # pragma: no cover - depends on runtime environment
        logger.exception("Packet processing failed: %s", exc)


def run_monitor() -> None:
    """Initialize the application and start the monitoring loop."""
    try:
        config = load_config()
        if not config.get("EMAIL_ADDRESS") and not config.get("EMAIL_PASSWORD"):
            logger.warning("Email environment variables are not set; SMTP notifications will be skipped.")

        interfaces = get_available_interfaces()
        interface_name = resolve_preferred_tshark_interface() or resolve_interface_name(interfaces)

        if not interface_name:
            logger.warning("No interface was detected; using auto-detect mode.")

        logger.info("Broadcast monitoring initialized on interface: %s", interface_name or "auto-detect")
        capture_packets(interface=interface_name, packet_handler=process_packet)
    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user.")
    except PacketCaptureError as exc:
        logger.error("Capture startup failed: %s", exc)
    except Exception as exc:  # pragma: no cover - depends on runtime environment
        logger.exception("Unexpected monitoring error: %s", exc)


def main() -> None:
    """Run the monitoring application."""
    run_monitor()


if __name__ == "__main__":
    main()
