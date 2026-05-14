from __future__ import annotations

import asyncio
import concurrent.futures
from pathlib import Path

from ctf_toolkit.ui.common import print_table
from ctf_toolkit.utils.io import info, safe_input, warn
from ctf_toolkit.utils.menu import run_menu


def menu() -> None:
    def log_forensic_menu() -> None:
        from ctf_toolkit.forensics.log_hunter import hunt_log_patterns, incident_rows, render_incident_report

        try:
            text = safe_input("Path log file (pisahkan koma untuk multi-file): ").strip()
            if not text:
                warn("Path log kosong.")
                return
            paths = [item.strip() for item in text.split(",") if item.strip()]
            brute_threshold = int(safe_input("Threshold bruteforce 401/403 [default 5]: ").strip() or "5")
            try:
                asyncio.get_running_loop()
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    incidents = pool.submit(
                        asyncio.run,
                        hunt_log_patterns(paths, brute_threshold=brute_threshold),
                    ).result()
            except RuntimeError:
                incidents = asyncio.run(hunt_log_patterns(paths, brute_threshold=brute_threshold))
            rows = incident_rows(incidents)
            print("\n=== Incident Report ===")
            if rows:
                print_table(["Time", "Source IP", "Attack Type", "Target URL"], rows)
            else:
                info("no incident detected")
            report_text = render_incident_report(incidents)
            output_path = safe_input("Simpan report ke file (opsional): ").strip()
            if output_path:
                Path(output_path).write_text(report_text, encoding="utf-8")
                print(f"[+] Report tersimpan: {output_path}")
        except (ValueError, FileNotFoundError, OSError) as exc:
            warn(f"Error: {exc}")

    def network_artifact_menu() -> None:
        from ctf_toolkit.forensics.network_artifacts import extract_network_artifacts, render_network_report

        try:
            pcap_path = safe_input("Path PCAP/PCAPNG: ").strip()
            output_root = safe_input("Output folder [default output]: ").strip() or "output"
            prefer_tshark_input = safe_input("Prioritaskan tshark jika tersedia? [Y/n]: ").strip().lower()
            prefer_tshark = prefer_tshark_input not in {"n", "no"}
            result = extract_network_artifacts(pcap_path, output_root=output_root, prefer_tshark=prefer_tshark)
            print(render_network_report(result))
            print(f"[+] Output folder: {result.output_dir}")
        except (ValueError, FileNotFoundError, OSError) as exc:
            warn(f"Error: {exc}")

    def digital_artifact_menu() -> None:
        from ctf_toolkit.forensics.artifact_discovery import artifact_rows, generate_hash_oneliner, quick_discovery

        try:
            target_os = (safe_input("Target OS [auto/windows/linux]: ").strip() or "auto").lower()
            detected_os, artifacts = quick_discovery(target_os=target_os)
            rows = artifact_rows(artifacts)
            print(f"\n=== Quick Discovery ({detected_os}) ===")
            print_table(["Category", "Path", "Notes"], rows)
            print("\n[+] One-liner hash (MD5 + SHA256):")
            print(generate_hash_oneliner(artifacts, detected_os))
        except (ValueError, FileNotFoundError, OSError) as exc:
            warn(f"Error: {exc}")

    def malware_helper_menu() -> None:
        from ctf_toolkit.forensics.malware_helper import (
            check_file_header,
            extract_interesting_strings,
            render_strings_report,
        )

        try:
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
        except (ValueError, FileNotFoundError, OSError) as exc:
            warn(f"Error: {exc}")

    run_menu(
        "Defensive / Blue Team",
        {
            "1": ("Log Forensic & Anomaly Detector", log_forensic_menu),
            "2": ("Network Artifact Extractor", network_artifact_menu),
            "3": ("Digital Artifact Discovery", digital_artifact_menu),
            "4": ("Malware Analysis Helper", malware_helper_menu),
        },
    )
