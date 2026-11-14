"""USB HID (Human Interface Device) packet forensic decoder.

Extracts typed keystrokes, commands, and passwords from captured USB traffic:
- USB HID Keyboard Report (8-byte descriptor):
    Byte 0: Modifier keys (Shift, Ctrl, Alt, GUI)
    Byte 1: Reserved
    Byte 2..7: Up to 6 concurrent active Keycodes (USB HID Usage Table 0x07)
- Supports raw packet dumps, tshark colon-separated text, raw hex streams, and PCAP files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

__all__ = [
    "decode_usb_hid_packets",
    "decode_usb_hid_from_text",
    "decode_usb_hid_pcap",
    "USB_HID_KEYCODES",
]

# USB HID Usage Table for Keyboard/Keypad (Page 0x07)
# Maps keycode -> (unshifted_char, shifted_char)
USB_HID_KEYCODES: dict[int, tuple[str, str]] = {
    0x04: ("a", "A"), 0x05: ("b", "B"), 0x06: ("c", "C"), 0x07: ("d", "D"),
    0x08: ("e", "E"), 0x09: ("f", "F"), 0x0A: ("g", "G"), 0x0B: ("h", "H"),
    0x0C: ("i", "I"), 0x0D: ("j", "J"), 0x0E: ("k", "K"), 0x0F: ("l", "L"),
    0x10: ("m", "M"), 0x11: ("n", "N"), 0x12: ("o", "O"), 0x13: ("p", "P"),
    0x14: ("q", "Q"), 0x15: ("r", "R"), 0x16: ("s", "S"), 0x17: ("t", "T"),
    0x18: ("u", "U"), 0x19: ("v", "V"), 0x1A: ("w", "W"), 0x1B: ("x", "X"),
    0x1C: ("y", "Y"), 0x1D: ("z", "Z"),
    0x1E: ("1", "!"), 0x1F: ("2", "@"), 0x20: ("3", "#"), 0x21: ("4", "$"),
    0x22: ("5", "%"), 0x23: ("6", "^"), 0x24: ("7", "&"), 0x25: ("8", "*"),
    0x26: ("9", "("), 0x27: ("0", ")"),
    0x28: ("\n", "\n"),  # Return / Enter
    0x2C: (" ", " "),    # Spacebar
    0x2D: ("-", "_"),
    0x2E: ("=", "+"),
    0x2F: ("[", "{"),
    0x30: ("]", "}"),
    0x31: ("\\", "|"),
    0x33: (";", ":"),
    0x34: ("'", '"'),
    0x35: ("`", "~"),
    0x36: (",", "<"),
    0x37: (".", ">"),
    0x38: ("/", "?"),
}


def decode_usb_hid_packets(packets: Sequence[bytes | bytearray]) -> str:
    """Decode a sequence of 8-byte USB HID keyboard reports into typed text.

    Correctly tracks state transitions, shift modifiers, and backspaces.
    """
    typed: list[str] = []
    prev_keys: set[int] = set()

    for pkt in packets:
        if len(pkt) < 8:
            continue
        modifier = pkt[0]
        # Bit 1 = Left Shift (0x02), Bit 5 = Right Shift (0x20)
        shift = bool(modifier & 0x22)
        curr_keys = set(pkt[2:8]) - {0x00}

        # Identify newly pressed keys
        new_keys = curr_keys - prev_keys
        for k in new_keys:
            if k == 0x2A:  # Backspace
                if typed:
                    typed.pop()
            elif k in USB_HID_KEYCODES:
                char = USB_HID_KEYCODES[k][1 if shift else 0]
                typed.append(char)

        prev_keys = curr_keys

    return "".join(typed)


def decode_usb_hid_from_text(text: str) -> str:
    """Parse text dumps of USB HID packets (colon-separated, space-separated, or hex).

    Handles formats from:
    - `tshark -r capture.pcap -T fields -e usb.capdata`
    - `tshark -r capture.pcap -T fields -e usbhid.data`
    """
    packets: list[bytes] = []
    lines = text.strip().splitlines()

    for line in lines:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", line)
        if len(cleaned) >= 16:
            # 8 bytes = 16 hex digits
            try:
                raw_bytes = bytes.fromhex(cleaned[:16])
                packets.append(raw_bytes)
            except ValueError:
                continue

    return decode_usb_hid_packets(packets)


def decode_usb_hid_pcap(pcap_source: bytes | str | Path) -> str:
    """Extract and decode USB HID keyboard reports directly from a PCAP/PCAPNG file."""
    if isinstance(pcap_source, (str, Path)):
        pcap_bytes = Path(pcap_source).read_bytes()
    else:
        pcap_bytes = bytes(pcap_source)

    packets: list[bytes] = []

    # Fast scanner for USB Interrupt packets carrying 8-byte HID descriptors
    # In PCAP with LINKTYPE_USB_LINUX (0xbd) or LINKTYPE_USB_LINUX_MMAPPED (0xdc):
    # Search for candidate 8-byte frames where byte 1 is 0x00 and bytes 2..7 are valid keycodes
    for i in range(len(pcap_bytes) - 8):
        # Look for standard HID report pattern: mod, 0x00, key1..key6
        if pcap_bytes[i + 1] == 0x00:
            keys = pcap_bytes[i + 2 : i + 8]
            if any(k in USB_HID_KEYCODES or k == 0x2A for k in keys if k != 0x00):
                # Valid candidate packet
                packets.append(pcap_bytes[i : i + 8])

    return decode_usb_hid_packets(packets)
