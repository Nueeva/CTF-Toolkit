from __future__ import annotations

import os

from ctf_toolkit.pipeline import run_recipe, RECIPE_REGISTRY
from ctf_toolkit.triage import triage_data, triage_file
from ctf_toolkit.utils.io import safe_input, success, warn, info


def triage_interactive() -> None:
    print("\n--- Auto-Triage & Fingerprinter ---")
    print("[1] Triage File")
    print("[2] Triage Raw Text / Hex / Base64")
    choice = safe_input("Pilih sumber input: ").strip()

    if choice == "1":
        fpath = safe_input("Masukkan path file: ").strip().strip('"')
        if not os.path.exists(fpath):
            warn(f"File tidak ditemukan: {fpath}")
            return
        report = triage_file(fpath)
        print("\n" + report.summary())
    elif choice == "2":
        raw = safe_input("Masukkan string / data mentah: ").strip()
        if not raw:
            warn("Input kosong.")
            return
        report = triage_data(raw.encode(), target_label="user_input")
        print("\n" + report.summary())
    else:
        warn("Pilihan tidak valid.")


def recipe_interactive() -> None:
    print("\n--- CyberChef-Style Recipe Engine ---")
    info(f"Operasi tersedia: {', '.join(sorted(RECIPE_REGISTRY.keys()))}")
    recipe_str = safe_input("Masukkan rantai resep (contoh: 'b64d | xor:0x5a | flag_scan'): ").strip()
    if not recipe_str:
        warn("Resep kosong.")
        return

    print("[1] Input dari String")
    print("[2] Input dari File")
    choice = safe_input("Pilih sumber input: ").strip()

    if choice == "1":
        data = safe_input("Masukkan data: ")
    elif choice == "2":
        fpath = safe_input("Masukkan path file: ").strip().strip('"')
        if not os.path.exists(fpath):
            warn(f"File tidak ditemukan: {fpath}")
            return
        with open(fpath, "rb") as f:
            data = f.read()
    else:
        warn("Pilihan tidak valid.")
        return

    try:
        result = run_recipe(recipe_str, data)
        success("\n[+] Hasil Eksekusi Resep:")
        if isinstance(result, bytes):
            try:
                print(result.decode("utf-8"))
            except UnicodeDecodeError:
                print(f"[HEX]: {result.hex()}")
                print(f"[RAW LATIN-1]: {result.decode('latin-1', errors='replace')}")
        else:
            print(str(result))
    except Exception as e:
        warn(f"Gagal menjalankan resep: {e}")


def menu() -> None:
    while True:
        print("\n=== CTF Workbench & Pipeline ===")
        print("[1] Auto-Triage & Fingerprint (Entropy / Magic / Encodings)")
        print("[2] CyberChef Recipe Pipeline (Chain operations)")
        print("[3] Daftar Operasi Resep Tersedia")
        print("[0] Kembali ke Menu Utama")

        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        elif choice == "1":
            triage_interactive()
        elif choice == "2":
            recipe_interactive()
        elif choice == "3":
            print("\nOperasi Terdaftar:")
            for op in sorted(RECIPE_REGISTRY.keys()):
                print(f"  - {op}")
        else:
            warn("Pilihan tidak valid, coba lagi.")
