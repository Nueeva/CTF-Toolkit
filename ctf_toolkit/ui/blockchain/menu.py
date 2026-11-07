from __future__ import annotations

from ctf_toolkit.blockchain.calldata import parse_calldata
from ctf_toolkit.utils.io import info, safe_input, warn


def menu() -> None:
    while True:
        print("\n=== Blockchain / EVM ===")
        print("[1] Parse Calldata / ABI Decoder")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        if choice == "1":
            raw_hex = safe_input("Calldata hex (0x...): ").strip()
            if not raw_hex:
                warn("Hex input tidak boleh kosong.")
                continue
            try:
                res = parse_calldata(raw_hex)
                print(f"[+] Selector: {res['selector']}")
                print(f"[+] Total Words: {res['word_count']} (Raw bytes: {res['raw_length']})")
                if res['ascii_strings']:
                    print("[+] Extracted ASCII Strings:")
                    for s in res['ascii_strings']:
                        print(f"    - {s}")
                else:
                    info("Tidak ditemukan string ASCII yang jelas di calldata.")
            except Exception as e:
                warn(f"Gagal parse calldata: {e}")
        else:
            warn("Pilihan tidak valid.")
