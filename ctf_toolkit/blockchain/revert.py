from __future__ import annotations

import re


def decode_revert_reason(hex_data: str) -> dict[str, object]:
    """Decode standard EVM revert error data (Error(string) or Panic(uint256))."""
    clean_hex = hex_data.strip()
    if clean_hex.startswith("0x") or clean_hex.startswith("0X"):
        clean_hex = clean_hex[2:]

    if len(clean_hex) < 8:
        return {"error_type": "unknown", "raw_hex": clean_hex}

    selector = clean_hex[:8].lower()
    payload = clean_hex[8:]

    # Error(string) -> selector 08c379a0
    if selector == "08c379a0":
        # standard abi string: 32 bytes offset, 32 bytes length, then data
        try:
            raw_bytes = bytes.fromhex(payload)
            ascii_matches = re.findall(b"[ -~]{4,}", raw_bytes)
            reason = ascii_matches[0].decode("utf-8") if ascii_matches else ""
            return {
                "error_type": "Error(string)",
                "selector": "0x08c379a0",
                "reason": reason,
                "raw_hex": clean_hex,
            }
        except Exception:
            pass

    # Panic(uint256) -> selector 4e487b71
    if selector == "4e487b71":
        panic_codes = {
            0x00: "Generic compiler panic",
            0x01: "Assert evaluated to false",
            0x11: "Arithmetic overflow/underflow",
            0x12: "Division by zero",
            0x21: "Invalid enum conversion",
            0x22: "Access to out-of-bounds storage byte array",
            0x31: "Pop on empty array",
            0x32: "Out of bounds array index access",
            0x41: "Allocation of too much memory",
            0x51: "Call to zero-initialized internal function pointer",
        }
        try:
            code = int(payload[:64], 16) if len(payload) >= 64 else int(payload, 16)
            return {
                "error_type": "Panic(uint256)",
                "selector": "0x4e487b71",
                "panic_code": code,
                "panic_description": panic_codes.get(code, "Unknown panic code"),
                "raw_hex": clean_hex,
            }
        except Exception:
            pass

    # Custom or unknown error: extract any ascii string
    try:
        raw_bytes = bytes.fromhex(clean_hex)
        ascii_matches = [m.decode("utf-8", errors="ignore") for m in re.findall(b"[ -~]{4,}", raw_bytes)]
        return {
            "error_type": "CustomError",
            "selector": f"0x{selector}",
            "extracted_strings": ascii_matches,
            "raw_hex": clean_hex,
        }
    except Exception:
        return {"error_type": "unknown", "selector": f"0x{selector}", "raw_hex": clean_hex}
