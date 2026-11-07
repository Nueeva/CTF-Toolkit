from __future__ import annotations

import os

from ctf_toolkit.osint_misc.bencode import parse_torrent
from ctf_toolkit.osint_misc.esolang import brainfuck_eval, ook_eval
from ctf_toolkit.utils.io import read_bytes_file, read_text_file, safe_input, warn


def menu() -> None:
    while True:
        print("\n=== OSINT & Misc ===")
        print("[1] Brainfuck Interpreter")
        print("[2] Ook! Interpreter")
        print("[3] Torrent / Bencode Metadata Extractor")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        if choice == "1":
            mode = safe_input("Input via [1] Teks langsung / [2] Path file: ").strip()
            src = read_text_file(safe_input("Path file .bf: ").strip()) if mode == "2" else safe_input("Source code: ").strip()
            if not src:
                warn("Source code kosong.")
                continue
            inp = safe_input("Input runtime [opsional]: ").strip()
            try:
                print(f"[+] Output:\n{brainfuck_eval(src, inp)}")
            except Exception as e:
                warn(f"Error eksekusi: {e}")

        elif choice == "2":
            mode = safe_input("Input via [1] Teks langsung / [2] Path file: ").strip()
            src = read_text_file(safe_input("Path file .ook: ").strip()) if mode == "2" else safe_input("Source code: ").strip()
            if not src:
                warn("Source code kosong.")
                continue
            inp = safe_input("Input runtime [opsional]: ").strip()
            try:
                print(f"[+] Output:\n{ook_eval(src, inp)}")
            except Exception as e:
                warn(f"Error eksekusi: {e}")

        elif choice == "3":
            p = safe_input("Path file .torrent: ").strip()
            if not os.path.exists(p):
                warn("File tidak ditemukan.")
                continue
            try:
                data = read_bytes_file(p)
                meta = parse_torrent(data)
                print("\n=== Torrent Metadata ===")
                for k, v in meta.items():
                    print(f"  {k}: {v}")
            except Exception as e:
                warn(f"Error parsing torrent: {e}")
        else:
            warn("Pilihan tidak valid.")
