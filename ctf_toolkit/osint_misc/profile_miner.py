from __future__ import annotations

import json
import re
from typing import Any


def mine_profile_handles(data: str | bytes | dict[str, Any]) -> dict[str, Any]:
    """
    Extract social handles, email addresses, URLs, and embedded flags from OSINT profile dumps.
    """
    if isinstance(data, dict):
        text = json.dumps(data)
    elif isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = str(data)

    handles = sorted(set(re.findall(r"(?<![A-Za-z0-9._%+-])@[A-Za-z0-9_.-]{3,32}", text)))
    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)))
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>]+", text)))
    flags = sorted(set(re.findall(r"(?:GETSFLAG|CTF|FLAG|CT)\{[^}\s]+\}", text, re.IGNORECASE)))

    return {
        "handles": handles,
        "emails": emails,
        "urls": urls,
        "flags": flags,
    }
