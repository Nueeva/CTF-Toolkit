from __future__ import annotations

from ctf_toolkit.utils.io import read_bytes_file, safe_input, warn


def menu() -> None:
    while True:
        print("\n=== Forensics / RE ===")
        print("[1] File Magic Detect")
        print("[2] Hexdump File")
        print("[3] Entropy File")
        print("[4] Strings Extractor")
        print("[5] PCAP Extractor")
        print("[6] PCAP Notes")
        print("[7] ZIP Recover (corrupted header/trailing)")
        print("[8] JPEG Tools (extract/patch dimensi)")
        print("[9] Caesar Shifter Helper")
        print("[10] PYC Decompiler (pycdc/uncompyle6)")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return

        path = safe_input("Path file: ").strip() if choice in {"1", "2", "3", "4"} else ""
        data = read_bytes_file(path) if path else b""

        if choice in {"1", "2", "3", "4"} and not data:
            warn("File kosong / gagal dibaca.")
            continue

        if choice == "1":
            from ctf_toolkit.forensics.filetype import detect_file_magic

            print(f"[+] File type: {detect_file_magic(data)}")
        elif choice == "2":
            from ctf_toolkit.utils.text import hexdump

            length = int(safe_input("Jumlah byte [default 256]: ").strip() or "256")
            print(hexdump(data[:length]))
        elif choice == "3":
            from ctf_toolkit.utils.text import shannon_entropy

            print(f"[+] Entropy: {shannon_entropy(data):.4f}")
        elif choice == "4":
            from ctf_toolkit.utils.text import extract_printable_strings

            min_len = int(safe_input("Min length [default 4]: ").strip() or "4")
            strings_found = extract_printable_strings(data, min_len=min_len)
            for idx, value in enumerate(strings_found[:500], start=1):
                print(f"{idx:03d}. {value}")
            if len(strings_found) > 500:
                print(f"[i] {len(strings_found)-500} hasil lain disembunyikan.")
        elif choice == "5":
            from ctf_toolkit.forensics.pcap_extract import extract_pcap_artifacts

            pcap_path = safe_input("Path PCAP/PCAPNG: ").strip()
            output_root = safe_input("Output folder [default output]: ").strip() or "output"
            out_dir = extract_pcap_artifacts(pcap_path, output_root=output_root)
            print(f"[+] Artifact tersimpan di: {out_dir}")
        elif choice == "6":
            from ctf_toolkit.forensics.pcap_notes import PCAP_HELP_TEXT

            print(PCAP_HELP_TEXT)
        elif choice == "7":
            from ctf_toolkit.forensics.zip_recover import list_zip_members, recover_corrupted_zip

            zip_path = safe_input("Path ZIP rusak: ").strip()
            recovered = recover_corrupted_zip(zip_path)
            print(f"[+] ZIP hasil recover: {recovered}")
            try:
                members = list_zip_members(str(recovered))
                print("[+] Isi ZIP:")
                for name in members[:200]:
                    print(f"  - {name}")
                if len(members) > 200:
                    print(f"[i] {len(members)-200} entri lain disembunyikan.")
            except Exception as exc:
                warn(f"ZIP belum bisa dibuka: {exc}")
        elif choice == "8":
            from ctf_toolkit.forensics.jpeg_tools import extract_jpeg_fragments, get_jpeg_dimensions, patch_jpeg_dimensions

            print("[1] Extract JPEG fragments")
            print("[2] Lihat dimensi JPEG")
            print("[3] Patch dimensi JPEG")
            sub = safe_input("Pilih opsi: ").strip()
            if sub == "1":
                source = safe_input("Path file sumber: ").strip()
                out_dir = safe_input("Output folder [default output/jpeg_fragments]: ").strip() or "output/jpeg_fragments"
                parts = extract_jpeg_fragments(source, output_dir=out_dir)
                print(f"[+] Fragment ditemukan: {len(parts)}")
                for fragment in parts[:50]:
                    print(f"  - {fragment}")
            elif sub == "2":
                source = safe_input("Path JPEG: ").strip()
                width, height = get_jpeg_dimensions(source)
                print(f"[+] Dimensi: {width}x{height}")
            elif sub == "3":
                source = safe_input("Path JPEG: ").strip()
                width = int(safe_input("Width baru: ").strip())
                height = int(safe_input("Height baru: ").strip())
                patched = patch_jpeg_dimensions(source, width=width, height=height)
                print(f"[+] JPEG patched: {patched}")
            else:
                warn("Pilihan tidak valid.")
        elif choice == "9":
            from ctf_toolkit.forensics.caesar_helper import suggest_caesar_candidates

            text = safe_input("Ciphertext Caesar: ")
            if not text:
                warn("Teks kosong.")
                continue
            top_n = int(safe_input("Tampilkan berapa kandidat? [default 5]: ").strip() or "5")
            for shift, candidate in suggest_caesar_candidates(text, top_n=top_n):
                print(f"[shift {shift:2d}] {candidate}")
        elif choice == "10":
            from ctf_toolkit.forensics.pyc_decompile import decompile_pyc
            from ctf_toolkit.utils.pager import page_text

            pyc_path = safe_input("Path .pyc: ").strip()
            if not pyc_path:
                warn("Path kosong.")
                continue
            try:
                tool, output = decompile_pyc(pyc_path)
                print(f"[+] Decompiler: {tool}")
                if not output.strip():
                    warn("Output kosong.")
                    continue
                page_text(output)
            except (ValueError, FileNotFoundError) as exc:
                warn(f"Error: {exc}")
        else:
            warn("Pilihan tidak valid.")
