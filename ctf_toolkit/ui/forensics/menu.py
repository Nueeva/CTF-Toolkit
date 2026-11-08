from __future__ import annotations

from ctf_toolkit.ui.console import render_header, render_menu_panel
from ctf_toolkit.ui.inspector import inspect_output
from ctf_toolkit.utils.io import info, read_bytes_file, safe_input, warn


def menu() -> None:
    from ctf_toolkit.main_cli import handle_global_hotkey

    items = [
        ("1", "File Magic Detect"),
        ("2", "Hexdump File"),
        ("3", "Entropy File"),
        ("4", "Strings Extractor"),
        ("5", "PCAP Artifact Extractor"),
        ("6", "PCAP Notes & Reference"),
        ("7", "ZIP Recover (corrupted header/trailing)"),
        ("8", "JPEG Tools (fragments / dimensions / COM)"),
        ("9", "Caesar Shifter Helper"),
        ("10", "PYC Decompiler & Byte-Transform Solver"),
        ("11", "PDF Metadata & Stream Extractor"),
        ("12", "Office Forensics (DOCX Vanish/Comments & XLSX Hidden Sheets)"),
        ("13", "PNG & Image Stego (Header Repair, Chunks, Trailing, LSB)"),
        ("14", "Audio WAV Forensics (LSB, DTMF, FSK, CW Morse)"),
        ("15", "Automated Embedded File Carver (binwalk -e style)"),
        ("16", "WebAssembly (.wasm) Binary Dissector"),
        ("0", "Kembali"),
    ]

    while True:
        render_header("Forensics & Reverse Engineering")
        render_menu_panel("Forensics / RE Workbench", items)
        choice = safe_input("Pilih opsi: ").strip()
        if choice == "0":
            return
        if handle_global_hotkey(choice):
            continue

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
                info(f"{len(strings_found)-500} hasil lain disembunyikan.")
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
                    info(f"{len(members)-200} entri lain disembunyikan.")
            except Exception as exc:
                warn(f"ZIP belum bisa dibuka: {exc}")
        elif choice == "8":
            from ctf_toolkit.forensics.jpeg_tools import (
                extract_jpeg_comments,
                extract_jpeg_fragments,
                get_jpeg_dimensions,
                patch_jpeg_dimensions,
            )

            print("[1] Extract JPEG fragments")
            print("[2] Lihat dimensi JPEG")
            print("[3] Patch dimensi JPEG")
            print("[4] Extract JPEG COM comments")
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
            elif sub == "4":
                source = safe_input("Path JPEG: ").strip()
                raw = read_bytes_file(source)
                inspect_output(extract_jpeg_comments(raw), title="JPEG Comments", op_name="extract_jpeg_comments")
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
            from ctf_toolkit.forensics.pyc_decompile import decompile_pyc, solve_pyc_byte_transform
            from ctf_toolkit.utils.pager import page_text

            pyc_path = safe_input("Path .pyc: ").strip()
            if not pyc_path:
                warn("Path kosong.")
                continue
            raw_pyc = read_bytes_file(pyc_path)
            if raw_pyc:
                cands = solve_pyc_byte_transform(raw_pyc)
                if cands:
                    inspect_output("\n".join(cands[:20]), title="PYC Marshal & Transform Candidates", op_name="solve_pyc_byte_transform")
            try:
                tool, output = decompile_pyc(pyc_path)
                print(f"[+] Decompiler: {tool}")
                if output.strip():
                    page_text(output)
            except (ValueError, FileNotFoundError) as exc:
                info(f"External decompiler note: {exc}")
        elif choice == "11":
            from ctf_toolkit.forensics.pdf_tools import extract_pdf_metadata, scan_pdf_raw_objects

            pdf_p = safe_input("Path file PDF: ").strip()
            pdf_bytes = read_bytes_file(pdf_p)
            if not pdf_bytes:
                warn("File PDF kosong / tidak ditemukan.")
                continue
            meta = extract_pdf_metadata(pdf_bytes)
            tokens = scan_pdf_raw_objects(pdf_bytes)
            inspect_output({"metadata": meta, "stream_tokens": tokens[:30]}, title="PDF Forensics Report", op_name="scan_pdf_raw_objects")
        elif choice == "12":
            from ctf_toolkit.forensics.docx_tools import (
                extract_docx_comments,
                extract_docx_embeddings,
                extract_docx_hidden_vanish,
                extract_docx_metadata,
                extract_docx_tracked_revisions,
            )
            from ctf_toolkit.forensics.xlsx_tools import (
                extract_xlsx_cell_comments,
                extract_xlsx_hidden_sheets,
                extract_xlsx_metadata,
            )

            f_path = safe_input("Path file .docx / .xlsx: ").strip()
            raw = read_bytes_file(f_path)
            if not raw:
                warn("File tidak ditemukan.")
                continue
            if f_path.lower().endswith(".xlsx"):
                report = {
                    "metadata": extract_xlsx_metadata(raw),
                    "hidden_sheets": extract_xlsx_hidden_sheets(raw),
                    "comments": extract_xlsx_cell_comments(raw),
                }
            else:
                report = {
                    "metadata": extract_docx_metadata(raw),
                    "vanish_text": extract_docx_hidden_vanish(raw),
                    "comments": extract_docx_comments(raw),
                    "revisions": extract_docx_tracked_revisions(raw),
                    "embeddings": list(extract_docx_embeddings(raw).keys()),
                }
            inspect_output(report, title="OOXML Office Forensics", op_name="office_forensics")
        elif choice == "13":
            from ctf_toolkit.forensics.png_tools import (
                extract_png_all_metadata,
                extract_png_trailing_payload,
                repair_png_header,
            )

            p_path = safe_input("Path file PNG: ").strip()
            raw = read_bytes_file(p_path)
            if not raw:
                warn("File tidak ditemukan.")
                continue
            repaired = repair_png_header(raw)
            report = {
                "metadata_chunks": extract_png_all_metadata(repaired),
                "trailing_bytes": extract_png_trailing_payload(repaired),
            }
            inspect_output(report, title="PNG Forensics Report", op_name="png_forensics")
        elif choice == "14":
            from ctf_toolkit.forensics.audio_tools import (
                decode_audio_cw_morse,
                extract_audio_pcm_lsb,
            )

            w_path = safe_input("Path file WAV: ").strip()
            raw = read_bytes_file(w_path)
            if not raw:
                warn("File WAV tidak ditemukan.")
                continue
            lsb_bytes = extract_audio_pcm_lsb(raw)[:128]
            cw_text = decode_audio_cw_morse(raw)
            inspect_output({"lsb_preview": lsb_bytes, "cw_morse": cw_text}, title="Audio WAV Forensics", op_name="audio_forensics")
        elif choice == "15":
            from ctf_toolkit.forensics.carver import carve_embedded_files

            c_path = safe_input("Path file biner: ").strip()
            raw = read_bytes_file(c_path)
            if not raw:
                warn("File tidak ditemukan.")
                continue
            carved = carve_embedded_files(raw, include_offset_zero=True)
            inspect_output(carved, title="Embedded File Carver (binwalk style)", op_name="carve_embedded_files")
        elif choice == "16":
            from ctf_toolkit.forensics.wasm_analyzer import analyze_wasm_binary

            w_path = safe_input("Path file .wasm: ").strip()
            raw = read_bytes_file(w_path)
            if not raw:
                warn("File .wasm tidak ditemukan.")
                continue
            try:
                inspect_output(analyze_wasm_binary(raw), title="WebAssembly Dissector", op_name="analyze_wasm_binary")
            except Exception as exc:
                warn(f"Gagal analisis .wasm: {exc}")
        else:
            warn("Pilihan tidak valid.")
