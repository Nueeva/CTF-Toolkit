from __future__ import annotations

from typing import Callable

from ctf_toolkit.ui.console import render_header, render_menu_panel
from ctf_toolkit.utils.io import safe_input, warn


def run_menu(title: str, options: dict[str, tuple[str, Callable[[], None]]]) -> None:
    """Render a standardized TUI v3 menu panel with global hotkey support."""
    from ctf_toolkit.main_cli import handle_global_hotkey

    while True:
        render_header(title)
        items = [(key, label) for key, (label, _) in options.items()]
        items.append(("0", "Kembali"))
        render_menu_panel(title, items, subtitle="Hotkeys: '/' Search | ':m' Magic | ':s' Studio | ':f' Flags")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        if handle_global_hotkey(choice):
            continue
        if choice in options:
            options[choice][1]()
        else:
            warn("Pilihan tidak valid.")
