"""FactorDB REST API integration for rapid integer factorization.

FactorDB (https://factordb.com) is the CTF industry standard for querying
known prime factors of composite moduli before burning CPU cycles.
Status codes:
  'FF': Fully Factored
  'CF': Composite, factors known
  'PR': Probably Prime
  'P': Prime
  'C': Composite, no factors known
  'U': Unknown
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any


def query_factordb(n: int, timeout: float = 5.0) -> dict[str, Any] | None:
    """Query factordb.com REST API for integer n."""
    if n <= 1:
        return None
    url = f"https://factordb.com/api?query={n}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Apexsions-CTF/1.0",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8")
            parsed = json.loads(data)
            return parsed
    except Exception:
        return None


def factordb_factor(n: int, timeout: float = 5.0) -> list[int] | None:
    """Retrieve full list of prime factors from FactorDB if available.

    Returns list of prime factors [p, q, ...] or None if not fully/partially factored.
    """
    res = query_factordb(n, timeout=timeout)
    if not res:
        return None

    status = res.get("status", "")
    # 'FF' = Fully Factored, 'CF' = Composite with known factors
    if status in ("FF", "CF"):
        raw_factors = res.get("factors", [])
        factors: list[int] = []
        for item in raw_factors:
            try:
                base = int(item[0])
                count = int(item[1])
                for _ in range(count):
                    factors.append(base)
            except (ValueError, IndexError):
                continue
        if len(factors) >= 2:
            return factors
    return None
