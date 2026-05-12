from __future__ import annotations

import asyncio
from pathlib import Path

from ctf_toolkit.ui.common import print_table
from ctf_toolkit.utils.io import safe_input, warn


def menu() -> None:
    while True:
        print("\n=== Defensive / Blue Team ===")
        print("[1] Log Forensic & Anomaly Detector")
        print("[2] Network Artifact Extractor")
        print("[3] Digital Artifact Discovery")
        print("[4] Malware Analysis Helper")
        print("[0] Kembali")
        choice = safe_input("Pilih opsi: ").strip()

        if choice == "0":
            return

        try:
            if choice == "1":
                from ctf_toolkit.forensics.log_hunter import hunt_log_patterns, incident_rows, render_incident_report

                text = safe_input("Path log file (pisahkan koma untuk multi-file): ").strip()
                if not text:
                    warn("Path log kosong.")
                    continue
                paths = [item.strip() for item in text.split(",") if item.strip()]
                brute_threshold = int(safe_input("Threshold bruteforce 401/403 [default 5]: ").strip() or "5")
                incidents = asyncio.run(hunt_log_patterns(paths, brute_threshold=brute_threshold))
                rows = incident_rows(incidents)
                print("\n=== Incident Report ===")
                if rows:
                    print_table(["Time", "Source IP", "Attack Type", "Target URL"], rows)
                else:
                    print("(no incident detected)")
                report_text = render_incident_report(incidents)
                output_path = safe_input("Simpan report ke file (opsional): ").strip()
                if output_path:
                    Path(output_path).write_text(report_text, encoding="utf-8")
                    print(f"[+] Report tersimpan: {output_path}")
            elif choice == "2":
                from ctf_toolkit.forensics.network_artifacts import extract_network_artifacts, render_network_report

                pcap_path = safe_input("Path PCAP/PCAPNG: ").strip()
                output_root = safe_input("Output folder [default output]: ").strip() or "output"
                prefer_tshark_input = safe_input("Prioritaskan tshark jika tersedia? [Y/n]: ").strip().lower()
                prefer_tshark = prefer_tshark_input not in {"n", "no"}
                result = extract_network_artifacts(pcap_path, output_root=output_root, prefer_tshark=prefer_tshark)
                print(render_network_report(result))
                print(f"[+] Output folder: {result.output_dir}")
            elif choice == "3":
                from ctf_toolkit.forensics.artifact_discovery import artifact_rows, generate_hash_oneliner, quick_discovery

                target_os = (safe_input("Target OS [auto/windows/linux]: ").strip() or "auto").lower()
                detected_os, artifacts = quick_discovery(target_os=target_os)
                rows = artifact_rows(artifacts)
                print(f"\n=== Quick Discovery ({detected_os}) ===")
                print_table(["Category", "Path", "Notes"], rows)
                print("\n[+] One-liner hash (MD5 + SHA256):")
                print(generate_hash_oneliner(artifacts, detected_os))
            elif choice == "4":
                from ctf_toolkit.forensics.malware_helper import (
                    check_file_header,
                    extract_interesting_strings,
                    render_strings_report,
                )

                print("[1] File Header Checker (Magic Bytes)")
                print("[2] Interesting Strings Analysis")
                sub = safe_input("Pilih opsi: ").strip()
                if sub == "1":
                    path = safe_input("Path file: ").strip()
                    result = check_file_header(path)
                    print_table(
                        ["Path", "Extension", "Expected", "Detected", "Mismatch", "Suspicious"],
                        [[
                            str(result["path"]),
                            str(result["extension"]),
                            str(result["expected_magic"]),
                            str(result["detected_magic"]),
                            str(result["mismatch"]),
                            str(result["suspicious"]),
                        ]],
                    )
                elif sub == "2":
                    path = safe_input("Path file suspicious: ").strip()
                    min_len = int(safe_input("Min string length [default 4]: ").strip() or "4")
                    strings_data = extract_interesting_strings(path, min_len=min_len)
                    print(render_strings_report(strings_data))
                else:
                    warn("Pilihan tidak valid.")
            else:
                warn("Pilihan tidak valid.")
        except (ValueError, FileNotFoundError, OSError) as exc:
            warn(f"Error: {exc}")
