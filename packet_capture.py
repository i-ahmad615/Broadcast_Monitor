"""Live packet capture utilities for the broadcast monitor."""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from typing import Any, Callable

logger = logging.getLogger("broadcast_monitor")


class PacketCaptureError(RuntimeError):
    """Raised when packet capture cannot be started."""


def extract_interface_name(interface_entry: Any) -> str:
    """Extract a usable interface name from a PyShark interface entry."""
    if isinstance(interface_entry, str):
        return interface_entry.strip()
    if isinstance(interface_entry, dict):
        for key in ("name", "interface", "description"):
            value = interface_entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def prefer_windows_interface_name(interface_name: str | None) -> str:
    """Return a Windows-friendly interface name when a display name is available."""
    if not interface_name:
        return ""
    if interface_name.startswith("\\Device\\NPF"):
        return interface_name
    return interface_name


def resolve_interface_name(interfaces: Any) -> str | None:
    """Resolve a first usable interface name from a PyShark interface list."""
    if not interfaces:
        return None
    if isinstance(interfaces, str):
        return interfaces.strip() or None
    if isinstance(interfaces, dict):
        return extract_interface_name(interfaces) or None

    preferred_terms = ("wi-fi", "ethernet")
    fallback_entries: list[str] = []

    for entry in interfaces:
        extracted = extract_interface_name(entry)
        if not extracted:
            continue

        normalized = extracted.lower()
        if any(term in normalized for term in preferred_terms):
            return extracted

        fallback_entries.append(extracted)

    for entry in fallback_entries:
        if "loopback" not in entry.lower() and "etwdump" not in entry.lower():
            return entry

    if fallback_entries:
        return fallback_entries[0]
    return None


def resolve_preferred_tshark_interface() -> str | None:
    """Return the best capture interface from Tshark's own interface list."""
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        return None

    try:
        result = subprocess.run(
            [tshark_path, "-D"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return None

    entries: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        if ". " not in line:
            continue
        remainder = line.split(". ", 1)[1].strip()
        device_name = remainder.split(" (", 1)[0].strip()
        display_name = remainder.split("(", 1)[1].rsplit(")", 1)[0].strip() if "(" in remainder and ")" in remainder else ""
        entries.append((device_name, display_name or device_name))

    for keyword in ("Wi-Fi", "Ethernet"):
        for device_name, display_name in entries:
            if keyword.lower() in display_name.lower() or keyword.lower() in device_name.lower():
                return display_name

    for device_name, display_name in entries:
        if "loopback" not in display_name.lower() and "etwdump" not in display_name.lower():
            return display_name

    return None


def resolve_tshark_display_name(interface_name: str | None) -> str:
    """Return a display-friendly interface name that Tshark accepts on Windows."""
    if not interface_name:
        return ""

    tshark_path = shutil.which("tshark")
    if not tshark_path:
        return interface_name

    try:
        result = subprocess.run(
            [tshark_path, "-D"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return interface_name

    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        if not line.startswith("\t") and ". " in line:
            remainder = line.split(". ", 1)[1].strip()
            device_name = remainder.split(" (", 1)[0].strip()
            display_name = remainder.split("(", 1)[1].rsplit(")", 1)[0].strip() if "(" in remainder and ")" in remainder else ""
            if interface_name in {device_name, display_name}:
                return display_name or device_name
            if interface_name.startswith("\\Device\\NPF") and device_name.startswith("\\Device\\NPF") and interface_name == device_name:
                return display_name or device_name
    return interface_name


def get_available_interfaces() -> list[dict[str, Any]]:
    """Return the available network interfaces from TShark."""
    try:
        from pyshark.tshark.tshark import get_tshark_interfaces

        return get_tshark_interfaces()
    except Exception as exc:  # pragma: no cover - depends on local environment
        logger.warning("Unable to enumerate interfaces: %s", exc)
        return []


def capture_packets(
    interface: str | None = None,
    packet_handler: Callable[[Any], None] | None = None,
    stop_event: threading.Event | None = None,
) -> None:
    """Capture packets continuously from a network interface."""
    if stop_event is None:
        stop_event = threading.Event()

    selected_interface = interface.strip() if interface else ""
    if not selected_interface:
        selected_interface = resolve_preferred_tshark_interface() or resolve_interface_name(get_available_interfaces()) or ""
    selected_interface = resolve_tshark_display_name(selected_interface) or selected_interface
    selected_interface = prefer_windows_interface_name(selected_interface)

    if not selected_interface:
        raise PacketCaptureError("No network interface was provided and none could be discovered.")

    tshark_path = shutil.which("tshark")
    if not tshark_path:
        raise PacketCaptureError("tshark was not found on PATH.")

    logger.info("Starting live packet capture on interface %s", selected_interface)

    field_names = [
        "frame.number",
        "eth.dst",
        "eth.src",
        "arp.src.proto_ipv4",
        "arp.dst.proto_ipv4",
        "arp.opcode",
        "frame.time_epoch",
    ]
    command = [
        tshark_path,
        "-i",
        selected_interface,
        "-l",
        "-Y",
        "arp",
        "-T",
        "fields",
    ]
    for field_name in field_names:
        command.extend(["-e", field_name])

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except Exception as exc:
        logger.exception("Unable to start Tshark subprocess: %s", exc)
        raise PacketCaptureError(f"Unable to start Tshark subprocess: {exc}") from exc

    try:
        while not stop_event.is_set():
            if process.poll() is not None:
                break

            line = process.stdout.readline() if process.stdout else ""
            if not line:
                time.sleep(0.1)
                continue

            raw_line = line.rstrip("\n")
            logger.info("Tshark raw output: %s", raw_line)
            parts = [part.strip() for part in raw_line.split("\t")]
            if not parts:
                continue

            packet_data = {
                field_names[index]: value
                for index, value in enumerate(parts)
                if index < len(field_names)
            }
            if packet_handler is not None:
                packet_handler(packet_data)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        logger.info("Packet capture stopped.")
