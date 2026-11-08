from __future__ import annotations

import math
import re
import struct
import zipfile
import io
from collections import Counter
from typing import Any

from ctf_toolkit.ui.console import (
    HAS_RICH,
    get_rich_console,
    sparkline,
    console_info,
    console_success,
    console_warn,
)
from ctf_toolkit.ui.session import set_last_output, scan_and_record_flags

try:
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
    from rich import box
except ImportError:
    pass


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def compute_entropy_blocks(data: bytes, num_blocks: int = 16) -> list[float]:
    """Calculate entropy for segmented slices of the payload to produce an entropy heatmap."""
    if not data:
        return [0.0]
    block_size = max(1, len(data) // num_blocks)
    entropies = []
    for i in range(0, len(data), block_size):
        chunk = data[i : i + block_size]
        if chunk:
            entropies.append(calculate_shannon_entropy(chunk))
    return entropies


def render_hexdump(data: bytes, max_bytes: int = 512) -> None:
    """Render a canonical colorized hexdump (offset, hex, ascii)."""
    console = get_rich_console()
    display_data = data[:max_bytes]
    truncated = len(data) > max_bytes

    if HAS_RICH and console:
        table = Table(
            box=box.SIMPLE_HEAD,
            title=f"Canonical Hexdump ({len(data)} bytes total{' - showing first ' + str(max_bytes) if truncated else ''})",
            border_style="dim",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Offset", style="dim yellow", justify="right", width=10)
        table.add_column("Hex Bytes (00-07  08-0F)", style="white", width=49)
        table.add_column("ASCII", style="cyan", width=18)

        for offset in range(0, len(display_data), 16):
            chunk = display_data[offset : offset + 16]
            hex_parts = []
            ascii_parts = []

            for i, b in enumerate(chunk):
                # Color code bytes by category
                if b == 0:
                    hex_str = f"[dim]00[/dim]"
                    ascii_char = "[dim].[/dim]"
                elif 32 <= b <= 126:
                    hex_str = f"[bright_green]{b:02x}[/bright_green]"
                    ascii_char = f"[bright_green]{chr(b)}[/bright_green]"
                elif b in (9, 10, 13):
                    hex_str = f"[yellow]{b:02x}[/yellow]"
                    ascii_char = "[yellow].[/yellow]"
                else:
                    hex_str = f"[bright_magenta]{b:02x}[/bright_magenta]"
                    ascii_char = "[dim magenta].[/dim magenta]"

                hex_parts.append(hex_str)
                ascii_parts.append(ascii_char)

            # Pad hex column if chunk < 16
            while len(hex_parts) < 16:
                hex_parts.append("  ")

            # Split 8 and 8
            left_hex = " ".join(hex_parts[:8])
            right_hex = " ".join(hex_parts[8:])
            hex_col = f"{left_hex}  {right_hex}"
            ascii_col = "".join(ascii_parts)

            table.add_row(f"{offset:08x}", hex_col, ascii_col)

        console.print(table)
        if truncated:
            console.print(f"[dim italic]... ({len(data) - max_bytes} bytes omitted) ...[/dim italic]")
    else:
        print(f"\n--- Hexdump ({len(data)} bytes) ---")
        for offset in range(0, len(display_data), 16):
            chunk = display_data[offset : offset + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            print(f"{offset:08x}  {hex_str:<48}  |{ascii_str}|")
        if truncated:
            print(f"... ({len(data) - max_bytes} bytes omitted) ...")


def dissect_binary_anatomy(data: bytes) -> dict[str, Any] | None:
    """Analyze file signatures and dissect container structure (PNG chunks, ZIP entries, PDF, ELF)."""
    if len(data) < 8:
        return None

    # 1. PNG Dissector
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        chunks = []
        pos = 8
        iend_offset = -1
        while pos + 8 <= len(data):
            c_len = struct.unpack(">I", data[pos : pos + 4])[0]
            c_type = data[pos + 4 : pos + 8].decode("latin1", errors="replace")
            crc_offset = pos + 8 + c_len
            chunks.append({"type": c_type, "length": c_len, "offset": pos})
            if c_type == "IEND":
                iend_offset = crc_offset + 4
                break
            pos = crc_offset + 4

        trailing_bytes = 0
        if iend_offset != -1 and iend_offset < len(data):
            trailing_bytes = len(data) - iend_offset

        return {
            "format": "PNG Image",
            "chunks": chunks,
            "iend_offset": iend_offset,
            "trailing_payload": trailing_bytes,
        }

    # 2. ZIP / OOXML Dissector
    if data.startswith(b"PK\x03\x04"):
        entries = []
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                for info in zf.infolist():
                    entries.append({
                        "filename": info.filename,
                        "file_size": info.file_size,
                        "compress_size": info.compress_size,
                        "is_encrypted": bool(info.flag_bits & 0x1),
                        "extra_len": len(info.extra),
                    })
        except Exception:
            pass
        return {
            "format": "ZIP Container / OOXML Archive",
            "entries_count": len(entries),
            "entries": entries[:12],
        }

    # 3. PDF Dissector
    if data.startswith(b"%PDF-"):
        streams = len(re.findall(rb"\bstream\b", data))
        objs = len(re.findall(rb"\bobj\b", data))
        return {
            "format": "PDF Document",
            "version": data[:8].decode("latin1", errors="ignore").strip(),
            "objects_count": objs,
            "streams_count": streams,
        }

    # 4. ELF Dissector
    if data.startswith(b"\x7fELF"):
        bits = "64-bit" if data[4] == 2 else "32-bit"
        endian = "Little-Endian" if data[5] == 1 else "Big-Endian"
        return {
            "format": "ELF Executable / Binary",
            "architecture": f"{bits} {endian}",
        }

    return None


def inspect_output(data: Any, title: str = "Result", op_name: str = "operation") -> None:
    """Unified Smart Output Inspector:
    - Stores output into $last session register
    - Scans for flags and renders a highlighted Flag Banner
    - Shows Entropy Heatmap + Canonical Hexdump for binary data
    - Displays Binary Anatomy for structured files (PNG/ZIP/PDF/ELF)
    - Formats strings and dictionaries/lists cleanly
    """
    console = get_rich_console()
    set_last_output(data, op_name=op_name)

    # 1. Scan and highlight flags
    flags = scan_and_record_flags(data, source=op_name)
    if flags:
        flag_banner = "  ".join(f"[bold bright_green]🏆 {f}[/bold bright_green]" for f in flags)
        if HAS_RICH and console:
            console.print(Panel(flag_banner, title="[bold green]FLAG CAPTURED![/bold green]", border_style="bright_green"))
        else:
            print("\n" + "*" * 60)
            print("  🏆 FLAG CAPTURED: " + ", ".join(flags))
            print("*" * 60)

    # 2. Inspect based on data type
    if isinstance(data, bytes):
        overall_entropy = calculate_shannon_entropy(data)
        blocks = compute_entropy_blocks(data, num_blocks=24)
        spk = sparkline(blocks, min_val=0.0, max_val=8.0)

        # Entropy interpretation
        if overall_entropy < 3.5:
            ent_label = "[green]Low (Plaintext/Padding)[/green]" if HAS_RICH else "Low (Plaintext/Padding)"
        elif overall_entropy < 6.5:
            ent_label = "[yellow]Medium (Code/Structured)[/yellow]" if HAS_RICH else "Medium (Code/Structured)"
        else:
            ent_label = "[bold red]High (Compressed/Encrypted Payload)[/bold red]" if HAS_RICH else "High (Compressed/Encrypted)"

        if HAS_RICH and console:
            console.print(
                f"[bold cyan]Entropy Heatmap:[/bold cyan] [bright_blue]{spk}[/bright_blue]  "
                f"[dim]H = {overall_entropy:.3f} bits/byte ({ent_label})[/dim]"
            )
        else:
            print(f"Entropy: {spk} H = {overall_entropy:.3f} ({ent_label})")

        # Binary Anatomy
        anatomy = dissect_binary_anatomy(data)
        if anatomy:
            if HAS_RICH and console:
                table = Table(title=f"🔬 Anatomy: {anatomy['format']}", box=box.ROUNDED, border_style="cyan")
                table.add_column("Property", style="bold yellow")
                table.add_column("Details", style="white")

                for k, v in anatomy.items():
                    if k in ("chunks", "entries"):
                        table.add_row(f"{k.capitalize()} Summary", f"{len(v)} item(s) detected")
                    else:
                        table.add_row(str(k), str(v))
                console.print(table)
            else:
                print(f"[Anatomy: {anatomy['format']}]")
                for k, v in anatomy.items():
                    if k not in ("chunks", "entries"):
                        print(f"  - {k}: {v}")

        # Render Hexdump
        render_hexdump(data)

    elif isinstance(data, dict):
        if HAS_RICH and console:
            table = Table(title=f"📋 {title} (Dict)", box=box.ROUNDED, border_style="blue")
            table.add_column("Key", style="bold yellow")
            table.add_column("Value", style="white")
            for k, v in data.items():
                table.add_row(str(k), str(v))
            console.print(table)
        else:
            print(f"\n--- {title} (Dict) ---")
            for k, v in data.items():
                print(f"  {k}: {v}")

    elif isinstance(data, list):
        if HAS_RICH and console:
            table = Table(title=f"📋 {title} ({len(data)} items)", box=box.SIMPLE, border_style="blue")
            table.add_column("#", style="dim yellow", justify="right", width=4)
            table.add_column("Item", style="white")
            for i, item in enumerate(data[:50], 1):
                table.add_row(str(i), str(item))
            if len(data) > 50:
                table.add_row("...", f"({len(data) - 50} more items)")
            console.print(table)
        else:
            print(f"\n--- {title} ({len(data)} items) ---")
            for i, item in enumerate(data[:50], 1):
                print(f"  {i}. {item}")
            if len(data) > 50:
                print(f"  ... ({len(data) - 50} more items)")

    else:
        text_val = str(data)
        if HAS_RICH and console:
            console.print(Panel(text_val, title=f"[bold bright_white]{title}[/bold bright_white]", border_style="green"))
        else:
            print(f"\n[+] {title}:")
            print(text_val)
