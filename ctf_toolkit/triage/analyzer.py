from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import Any


MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"\x89PNG\r\n\x1a\n", "PNG Image", "forensics"),
    (b"\xff\xd8\xff", "JPEG Image", "forensics"),
    (b"GIF87a", "GIF Image (87a)", "forensics"),
    (b"GIF89a", "GIF Image (89a)", "forensics"),
    (b"PK\x03\x04", "ZIP Archive", "forensics"),
    (b"\x1f\x8b\x08", "GZIP Compressed File", "forensics"),
    (b"BZh", "BZIP2 Compressed File", "forensics"),
    (b"\x7fELF", "ELF Executable/Binary", "binex/reversing"),
    (b"%PDF", "PDF Document", "forensics"),
    (b"\xd4\xc3\xb2\xa1", "PCAP Capture (Microseconds)", "forensics"),
    (b"\xa1\xb2\xc3\xd4", "PCAP Capture (Nanoseconds)", "forensics"),
    (b"\n\r\r\n", "PCAPNG Capture", "forensics"),
    (b"SQLite format 3\x00", "SQLite 3 Database", "forensics"),
    (b"ustar", "TAR Archive", "forensics"),
]


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte [0.0 - 8.0]."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def index_of_coincidence(text: str) -> float:
    """Calculate Index of Coincidence (IoC) for alphabetic characters."""
    letters = [ch.upper() for ch in text if "A" <= ch.upper() <= "Z"]
    n = len(letters)
    if n <= 1:
        return 0.0
    counts = Counter(letters)
    numerator = sum(c * (c - 1) for c in counts.values())
    denominator = n * (n - 1)
    return numerator / denominator


class TriageReport:
    """Structured findings from triage analysis."""

    def __init__(self, target_type: str, length: int) -> None:
        self.target_type = target_type
        self.length = length
        self.entropy = 0.0
        self.ioc = 0.0
        self.magic_type: str | None = None
        self.category_hint: str | None = None
        self.encodings_detected: list[str] = []
        self.flags_found: list[str] = []
        self.suggestions: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "length": self.length,
            "entropy": round(self.entropy, 4),
            "ioc": round(self.ioc, 4) if self.ioc else None,
            "magic_type": self.magic_type,
            "category_hint": self.category_hint,
            "encodings": self.encodings_detected,
            "flags": self.flags_found,
            "suggestions": self.suggestions,
        }

    def summary(self) -> str:
        lines: list[str] = []
        lines.append(f"=== TRIAGE REPORT ({self.target_type}, {self.length} bytes) ===")
        if self.magic_type:
            lines.append(f"  [+] File Type: {self.magic_type} (Category: {self.category_hint})")
        lines.append(f"  [*] Shannon Entropy: {self.entropy:.4f} / 8.0")
        if self.entropy > 7.5:
            lines.append("      -> High entropy: Likely encrypted, packed, or compressed.")
        elif self.entropy < 3.5:
            lines.append("      -> Low entropy: Sparse or repetitive data.")
        else:
            lines.append("      -> Moderate entropy: Natural text or encoded data.")
        if self.ioc > 0:
            lines.append(f"  [*] Index of Coincidence (IoC): {self.ioc:.4f}")
            if self.ioc >= 0.060:
                lines.append("      -> Close to English text (~0.067): Monoalphabetic or plaintext.")
            elif self.ioc <= 0.045:
                lines.append("      -> Low IoC (~0.038): Polyalphabetic (Vigenère) or pseudo-random.")
        if self.encodings_detected:
            lines.append(f"  [!] Encodings Detected: {', '.join(self.encodings_detected)}")
        if self.flags_found:
            lines.append(f"  [>>>] FLAG FOUND: {', '.join(self.flags_found)}")
        if self.suggestions:
            lines.append("  [?] Suggested Next Steps:")
            for s in self.suggestions:
                lines.append(f"      - {s}")
        return "\n".join(lines)


def triage_data(raw_data: bytes, target_label: str = "buffer") -> TriageReport:
    """Run comprehensive triage analysis on raw byte buffer."""
    report = TriageReport(target_label, len(raw_data))
    report.entropy = shannon_entropy(raw_data)

    # 1. Magic bytes
    for sig, label, cat in MAGIC_SIGNATURES:
        if raw_data.startswith(sig) or (sig == b"ustar" and len(raw_data) > 265 and raw_data[257:262] == b"ustar"):
            report.magic_type = label
            report.category_hint = cat
            break

    # 2. Check for embedded plaintext flags
    text_view = raw_data.decode("latin-1", errors="ignore")
    flags = re.findall(r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^\}\s]{3,}\}", text_view, re.IGNORECASE)
    if flags:
        report.flags_found.extend(flags)

    # 3. Unicode & zero-width check
    text_utf8 = raw_data.decode("utf-8", errors="ignore")
    if "\u200b" in text_utf8 or "\u200c" in text_utf8 or "\u200d" in text_utf8 or "\ufeff" in text_utf8:
        report.encodings_detected.append("Zero-Width Steganography")
        report.suggestions.append("Run zero-width decoder: 'decode_zero_width'")

    # 4. Text analysis
    printable_chars = [b for b in raw_data if 32 <= b <= 126 or b in (9, 10, 13)]
    printable_ratio = len(printable_chars) / len(raw_data) if raw_data else 0

    if printable_ratio > 0.80:
        # It's predominantly ASCII text
        text_clean = text_view.strip()
        report.ioc = index_of_coincidence(text_clean)

        # Check Hex
        if re.fullmatch(r"[0-9a-fA-F\s]{8,}", text_clean):
            report.encodings_detected.append("Hexadecimal")
            report.suggestions.append("Try recipe: 'hex_decode | flag_scan'")

        # Check Base64
        if re.fullmatch(r"[A-Za-z0-9+/=\s]{16,}", text_clean) and len(text_clean.replace("\n", "").replace(" ", "")) % 4 == 0:
            report.encodings_detected.append("Base64")
            report.suggestions.append("Try recipe: 'b64d | flag_scan'")

        # Check Ascii85
        if text_clean.startswith("<~") and text_clean.endswith("~>"):
            report.encodings_detected.append("Ascii85 (Adobe format)")
            report.suggestions.append("Try recipe: 'ascii85_decode | flag_scan'")

        # Check Morse
        if re.fullmatch(r"[\.\-\s/]+", text_clean) and len(text_clean) > 8:
            report.encodings_detected.append("Morse Code")
            report.suggestions.append("Run morse decoder: 'morse_decode'")

    # 5. Check for embedded archives or executables (Polyglot / Carving)
    if b"PK\x03\x04" in raw_data and not raw_data.startswith(b"PK\x03\x04"):
        report.suggestions.append("Embedded ZIP detected! Extract with zip tools.")
    if b"\x7fELF" in raw_data and not raw_data.startswith(b"\x7fELF"):
        report.suggestions.append("Embedded ELF binary detected! Run checksec / strings.")

    return report


def triage_file(filepath: str) -> TriageReport:
    """Run triage analysis on a file path."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    with open(filepath, "rb") as f:
        data = f.read()
    fname = os.path.basename(filepath)
    return triage_data(data, target_label=fname)
