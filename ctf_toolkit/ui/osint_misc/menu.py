from __future__ import annotations

from ctf_toolkit.osint_misc.esolang import brainfuck_eval
from ctf_toolkit.utils.io import read_text_file, safe_input, warn


def menu() -> None:
    while True:
        print("\n=== OSINT & Misc ===")
        print("[1] Brainfuck Interpreter (File/Input)")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        if choice == "1":
            mode = safe_input("Input via [1] Teks langsung / [2] Path file: ").strip()
            src = ""
            if mode == "2":
                p = safe_input("Path file .bf: ").strip()
                src = read_text_file(p)
            else:
                src = safe_input("Source code: ").strip()

            if not src:
                warn("Source code kosong.")
                continue

            inp = safe_input("Input runtime [opsional]: ").strip()
            try:
                out = brainfuck_eval(src, inp)
                print(f"[+] Output:\n{out}")
            except Exception as e:
                warn(f"Error eksekusi: {e}")
        else:
            warn("Pilihan tidak valid.")
