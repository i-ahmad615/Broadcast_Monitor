"""Broadcast detection logic for the monitor."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
BROADCAST_LABEL = "BROADCAST"
UNKNOWN_PROTOCOL = "UNKNOWN"


def _normalize_mac(value: Any) -> str:
    """Normalize MAC-like values so broadcast labels are detected consistently."""
    if value is None:
        return ""

    normalized = str(value).strip()
    if not normalized:
        return ""

    if normalized.upper() == BROADCAST_LABEL:
        return BROADCAST_MAC

    return normalized.upper()


def _safe_getattr(obj: Any, attribute: str, default: str = "") -> str:
    """Safely read an attribute from an object."""
    value = getattr(obj, attribute, None)
    return str(value or default)


def _extract_from_mapping(packet: Any) -> dict[str, str]:
    """Extract fields from a Tshark-style mapping payload."""
    mapping = packet if isinstance(packet, dict) else {}
    destination_mac = _normalize_mac(mapping.get("eth.dst", ""))
    source_mac = _normalize_mac(mapping.get("eth.src", ""))
    source_ip = mapping.get("arp.src.proto_ipv4", "") or mapping.get("ip.src", "") or ""
    protocol = ""

    if mapping.get("arp.opcode"):
        protocol = "ARP"
    elif mapping.get("ip.proto"):
        protocol = mapping.get("ip.proto", "") or UNKNOWN_PROTOCOL
    else:
        protocol = UNKNOWN_PROTOCOL

    return {
        "source_ip": source_ip,
        "source_mac": source_mac,
        "destination_mac": destination_mac,
        "protocol": protocol,
    }


def is_broadcast_packet(packet: Any) -> bool:
    """Return True when the packet targets the Ethernet broadcast MAC."""
    try:
        if isinstance(packet, dict):
            destination = _normalize_mac(packet.get("eth.dst", ""))
            return destination == BROADCAST_MAC

        if isinstance(packet, (list, tuple)):
            destination = _normalize_mac(packet[1] if len(packet) > 1 else "")
            return destination == BROADCAST_MAC

        eth_layer = getattr(packet, "eth", None)
        if eth_layer is None:
            return False

        destination = getattr(eth_layer, "dst", None)
        if destination is None:
            return False

        return _normalize_mac(destination) == BROADCAST_MAC
    except Exception:
        return False


def extract_packet_details(packet: Any) -> dict[str, str]:
    """Extract key packet metadata for broadcast logging and alerts."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S%z")

    if isinstance(packet, dict):
        extracted = _extract_from_mapping(packet)
        return {
            "timestamp": timestamp,
            "source_ip": extracted["source_ip"],
            "source_mac": extracted["source_mac"],
            "destination_mac": extracted["destination_mac"],
            "protocol": extracted["protocol"],
        }

    if isinstance(packet, (list, tuple)):
        destination_mac = _normalize_mac(packet[1] if len(packet) > 1 else "")
        source_mac = _normalize_mac(packet[2] if len(packet) > 2 else "")
        source_ip = packet[3] if len(packet) > 3 else ""
        protocol = "ARP" if len(packet) > 5 and packet[5] else UNKNOWN_PROTOCOL
        return {
            "timestamp": timestamp,
            "source_ip": str(source_ip),
            "source_mac": str(source_mac),
            "destination_mac": str(destination_mac),
            "protocol": str(protocol),
        }

    source_ip = ""
    source_mac = ""
    destination_mac = ""
    protocol = ""

    try:
        eth_layer = getattr(packet, "eth", None)
        if eth_layer is not None:
            source_mac = _safe_getattr(eth_layer, "src")
            destination_mac = _safe_getattr(eth_layer, "dst")

        ip_layer = getattr(packet, "ip", None)
        if ip_layer is not None:
            source_ip = _safe_getattr(ip_layer, "src")
            protocol = _safe_getattr(ip_layer, "proto")

        if not protocol:
            transport_layer = getattr(packet, "tcp", None) or getattr(packet, "udp", None)
            if transport_layer is not None:
                protocol = _safe_getattr(transport_layer, "_layer_name")

        if not protocol:
            protocol = UNKNOWN_PROTOCOL
    except Exception:
        source_ip = ""
        source_mac = ""
        destination_mac = ""
        protocol = UNKNOWN_PROTOCOL

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_mac": source_mac,
        "destination_mac": destination_mac,
        "protocol": protocol,
    }
