from __future__ import annotations

from typing import Callable

from ctf_toolkit.utils.io import safe_input, warn


def run_menu(title: str, options: dict[str, tuple[str, Callable[[], None]]]) -> None:
    while True:
        print(f"\n=== {title} ===")
        for key, (label, _) in options.items():
            print(f"[{key}] {label}")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        if choice in options:
            options[choice][1]()
        else:
            warn("Pilihan tidak valid.")
