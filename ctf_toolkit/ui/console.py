from __future__ import annotations

import os
import sys
from typing import Any

from ctf_toolkit.ui.session import get_session, copy_to_clipboard

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    _CONSOLE = Console()
    HAS_RICH = True
except ImportError:
    _CONSOLE = None
    HAS_RICH = False


def get_rich_console():
    return _CONSOLE


def sparkline(values: list[float], min_val: float = 0.0, max_val: float = 8.0) -> str:
    """Generate a terminal sparkline string from a list of numerical values."""
    if not values:
        return ""
    bars = [" ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    res = []
    val_range = max(max_val - min_val, 1e-6)
    for v in values:
        norm = max(0.0, min(1.0, (v - min_val) / val_range))
        idx = int(norm * (len(bars) - 1))
        res.append(bars[idx])
    return "".join(res)


def render_header(module_name: str = "Main Hub") -> None:
    """Render the Apex Command Center telemetry header."""
    session = get_session()
    last_val = session.registers.get("$last", None)

    if last_val is None:
        last_str = "[dim]<empty>[/dim]" if HAS_RICH else "<empty>"
    elif isinstance(last_val, bytes):
        preview = last_val[:16].hex()
        last_str = f"bytes({len(last_val)}B) 0x{preview}..."
    elif isinstance(last_val, str):
        preview = last_val[:20].replace("\n", "\\n")
        last_str = f"str({len(last_val)}c) '{preview}'"
    elif isinstance(last_val, (list, dict)):
        last_str = f"{type(last_val).__name__}({len(last_val)} items)"
    else:
        last_str = str(last_val)[:24]

    flag_count = len(session.captured_flags)
    flag_badge = f"[bold green]{flag_count} Flag(s)[/bold green]" if HAS_RICH else f"{flag_count} Flag(s)"

    if HAS_RICH and _CONSOLE:
        table = Table(box=box.HORIZONTALS, show_header=False, expand=True)
        table.add_column("Left", justify="left")
        table.add_column("Right", justify="right")
        table.add_row(
            f"[bold cyan]⚡ APEX CTF WORKBENCH[/bold cyan] [bold white]│ {module_name}[/bold white]",
            f"Case: [bold yellow]{session.active_case}[/bold yellow] │ Vault: {flag_badge}",
        )
        table.add_row(
            f"[dim]Buffer $last:[/dim] [bright_blue]{last_str}[/bright_blue]",
            "[dim]\\[/] Search Tools  \\[:m] Magic  \\[:s] Studio  \\[:f] Flags  \\[:c] Copy  \\[0] Back[/dim]",
        )
        _CONSOLE.print(Panel(table, border_style="cyan", padding=(0, 1)))
    else:
        print("=" * 68)
        print(f"APEX CTF WORKBENCH | {module_name} | Case: {session.active_case} | Vault: {flag_count} Flags")
        print(f"Buffer $last: {last_str}")
        print("Hotkeys: [/] Search 106+ Tools | [:m] Magic | [:s] Studio | [:f] Flags | [0] Back")
        print("=" * 68)


def render_menu_panel(title: str, items: list[tuple[str, str]], subtitle: str = "") -> None:
    """Render a menu selection grid (2-column layout in rich, list in plain)."""
    if HAS_RICH and _CONSOLE:
        table = Table(box=box.ROUNDED, border_style="bright_blue", show_header=False, expand=True)
        table.add_column("Key1", style="bold yellow", width=6)
        table.add_column("Desc1", style="white")
        table.add_column("Key2", style="bold yellow", width=6)
        table.add_column("Desc2", style="white")

        half = (len(items) + 1) // 2
        for i in range(half):
            k1, d1 = items[i]
            if i + half < len(items):
                k2, d2 = items[i + half]
            else:
                k2, d2 = "", ""
            table.add_row(f"[{k1}]", d1, f"[{k2}]" if k2 else "", d2)

        _CONSOLE.print(Panel(table, title=f"[bold bright_white]{title}[/bold bright_white]", subtitle=subtitle, border_style="blue"))
    else:
        print(f"\n=== {title} ===")
        for key, desc in items:
            print(f"[{key}] {desc}")
        if subtitle:
            print(f"({subtitle})")


def console_info(msg: str) -> None:
    if HAS_RICH and _CONSOLE:
        _CONSOLE.print(f"[bold cyan][i][/bold cyan] {msg}")
    else:
        print(f"[i] {msg}")


def console_success(msg: str) -> None:
    if HAS_RICH and _CONSOLE:
        _CONSOLE.print(f"[bold green][+][/bold green] {msg}")
    else:
        print(f"[+] {msg}")


def console_warn(msg: str) -> None:
    if HAS_RICH and _CONSOLE:
        _CONSOLE.print(f"[bold yellow][!][/bold yellow] {msg}")
    else:
        print(f"[!] {msg}")


def console_error(msg: str) -> None:
    if HAS_RICH and _CONSOLE:
        _CONSOLE.print(f"[bold red][-][/bold red] {msg}")
    else:
        print(f"[-] {msg}")


def show_flag_vault_interactive() -> None:
    """Display interactive Flag Vault with captured flags."""
    session = get_session()
    if not session.captured_flags:
        console_warn("Flag Vault kosong. Belum ada flag yang tertangkap pada sesi ini.")
        return

    if HAS_RICH and _CONSOLE:
        table = Table(title="🏆 Session Flag Vault", box=box.HEAVY_EDGE, border_style="green")
        table.add_column("#", style="bold yellow", justify="right", width=4)
        table.add_column("Captured Flag", style="bold bright_green")
        table.add_column("Source Tool", style="cyan")
        table.add_column("Timestamp", style="dim")
        for i, item in enumerate(session.captured_flags, 1):
            table.add_row(str(i), item["flag"], item["source"], item["time"])
        _CONSOLE.print(table)
    else:
        print("\n=== Session Flag Vault ===")
        for i, item in enumerate(session.captured_flags, 1):
            print(f"  {i}. {item['flag']} (from: {item['source']} @ {item['time']})")


def show_buffer_history_interactive() -> None:
    """Display register history ($last, $1, $2, ...)."""
    session = get_session()
    if not session.history:
        console_warn("Buffer history kosong.")
        return

    if HAS_RICH and _CONSOLE:
        table = Table(title="📜 Session Buffer Registers", box=box.SIMPLE, border_style="bright_blue")
        table.add_column("Reg", style="bold yellow", width=6)
        table.add_column("Operation", style="white")
        table.add_column("Type", style="cyan", width=10)
        table.add_column("Size", style="magenta", justify="right", width=10)
        table.add_column("Preview", style="dim")
        for item in session.history:
            prev = str(item["data"])[:40].replace("\n", "\\n")
            table.add_row(f"${item['index']}", item["op"], item["type"], f"{item['size']} B", prev)
        _CONSOLE.print(table)
    else:
        print("\n=== Session Buffer Registers ===")
        for item in session.history:
            print(f"  ${item['index']}: [{item['op']}] {item['type']} ({item['size']} B)")
