from __future__ import annotations

from ctf_toolkit.registry import get_menu_registry
from ctf_toolkit.utils.io import safe_input, success, warn


def show_main_menu() -> None:
    print("\n=== CTF Toolkit CLI ===")
    for entry in get_menu_registry():
        print(f"[{entry.key}] {entry.label}")
    print("[0] Exit")


def main() -> None:
    while True:
        show_main_menu()
        choice = safe_input("Pilih opsi menu: ").strip()

        if choice == "0":
            success("Keluar dari toolkit. Bye!")
            return

        selected = next((entry for entry in get_menu_registry() if entry.key == choice), None)
        if selected is None:
            warn("Pilihan tidak valid, coba lagi.")
            continue

        selected.loader()
