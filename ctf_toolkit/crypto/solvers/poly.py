"""Multiplicative-group and matrix solvers: Diffie-Hellman, ElGamal, Hill."""

from __future__ import annotations

import ast
import re

from ..ast_tracer import extract_bytes_constants
from ..cascade import Candidate, SolveContext
from ..mathutil import candidate_texts, modinv


def _get_int(ctx: SolveContext, *names: str) -> int | None:
    """Look up a parameter by role alias, case-insensitively, in every store."""
    def coerce(value) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            try:
                return int(value)
            except ValueError:
                return None
        return None

    sources = [ctx.params]
    traced = (ctx.report.get("trace") or {}).get("params", {})
    sources.append(traced)
    sources.extend({k.lower(): v for k, v in s.items()} for s in (ctx.params, traced))
    for name in names:
        for source in sources:
            got = coerce(source.get(name.lower()))
            if got is not None:
                return got
    return None


def solve_dh(ctx: SolveContext) -> list[Candidate]:
    """Small-prime DH: recover the exponent by discrete log, then derive shared secret."""
    p_raw = _get_int(ctx, "p")
    g_raw = _get_int(ctx, "g")
    A_raw = _get_int(ctx, "A", "alice", "pub_a")
    B_raw = _get_int(ctx, "B", "bob", "pub_b")
    if not all(isinstance(x, int) for x in (p_raw, g_raw, A_raw, B_raw)):
        return []
    p, g, A, B = int(p_raw), int(g_raw), int(A_raw), int(B_raw)  # type: ignore[arg-type]

    from ..mathutil import is_probable_prime
    if not is_probable_prime(p):
        return []

    secret = None
    try:
        from ..dlog_engine import smoothness_bound, pohlig_hellman_dlog, bsgs as dlog_bsgs
        if smoothness_bound(p - 1, limit=1000000) > 0:
            a, _ = pohlig_hellman_dlog(g, A, p)
            secret = pow(B, a, p)
            ctx.log.append(f"  dh discrete log via pohlig-hellman: a={a}")
        elif p <= 10000000:
            a = dlog_bsgs(g, A, p)
            secret = pow(B, a, p)
            ctx.log.append(f"  dh discrete log via bsgs: a={a}")
    except Exception:
        pass

    if secret is None:
        try:
            import sympy  # optional accelerant
            a = int(sympy.ntheory.discrete_log(p, A, g))
            secret = pow(B, a, p)
            ctx.log.append(f"  dh discrete log via sympy: a={a}")
        except Exception:
            secret = _bsgs(g, A, p, ctx)
            if secret is not None:
                secret = pow(B, secret, p)

    if secret is None:
        return []

    out: list[Candidate] = []
    # Contiguous SHA256-derived AES keys are the common derivation
    import hashlib
    for label, key in (
        ("sha256(str)[:16]", hashlib.sha256(str(secret).encode()).digest()[:16]),
        ("sha256(bytes)[:16]", hashlib.sha256(secret.to_bytes((secret.bit_length() + 7) // 8, "big")).digest()[:16]),
        ("str", str(secret).encode()),
        ("bytes", secret.to_bytes((secret.bit_length() + 7) // 8, "big")),
    ):
        cand = _try_aes_with_key(ctx, key)
        if cand:
            out.append(Candidate(cand, f"dh-shared-key[{label}]"))
    return out


def _bsgs(g: int, h: int, p: int, ctx: SolveContext) -> int | None:
    import math
    n = int(math.isqrt(p)) + 1
    table = {}
    e = 1
    for i in range(n):
        table.setdefault(e, i)
        e = (e * g) % p
    factor = modinv(pow(g, p - 1 - n, p) if False else pow(pow(g, n, p), -1, p), p)
    gamma = h
    for i in range(n):
        if gamma in table:
            x = i * n + table[gamma]
            if pow(g, x, p) == h:
                return x
        gamma = (gamma * factor) % p
    return None


def _try_aes_with_key(ctx: SolveContext, key: bytes) -> bytes | None:
    from ..pure_aes import aes_decrypt_cbc, aes_decrypt_ecb, strip_padding
    ct = _ciphertext_bytes(ctx)
    if not ct or len(ct) % 16:
        return None
    for mode_fn, label in ((aes_decrypt_ecb, "ecb"),):
        if len(key) in (16, 24, 32):
            try:
                plain = mode_fn(ct, key)
                for name, unpadded in strip_padding(plain):
                    if name != "raw":
                        return unpadded
            except Exception:
                pass
    if len(key) == 16:
        for iv in (b"\x00" * 16, ct[:16]):
            body = ct if iv == b"\x00" * 16 else ct[16:]
            try:
                plain = aes_decrypt_cbc(body, key, iv)
                for name, unpadded in strip_padding(plain):
                    if name != "raw":
                        return unpadded
            except Exception:
                pass
    return None


def _ciphertext_bytes(ctx: SolveContext) -> bytes:
    if ctx.output_bytes and len(ctx.output_bytes) % 16 == 0 and any(b > 127 for b in ctx.output_bytes[:16]):
        return ctx.output_bytes
    m = re.search(r"(?:ct|ciphertext|enc)\s*[=:]\s*([0-9a-fA-F]{32,})", ctx.output_text)
    if m:
        try:
            return bytes.fromhex(m.group(1))
        except ValueError:
            return b""
    for blob in re.findall(r"\b[0-9a-fA-F]{32,}\b", ctx.output_text):
        try:
            raw = bytes.fromhex(blob)
            if len(raw) % 16 == 0:
                return raw
        except ValueError:
            continue
    return b""


def solve_elgamal(ctx: SolveContext) -> list[Candidate]:
    """Private exponent leaked: m = c2 * (c1^x)^-1 mod p."""
    p_raw = _get_int(ctx, "p")
    c1_raw = _get_int(ctx, "c1")
    c2_raw = _get_int(ctx, "c2")
    x_raw = _get_int(ctx, "x", "priv", "d")
    if not all(isinstance(v, int) for v in (p_raw, c1_raw, c2_raw, x_raw)):
        return []
    p, c1, c2, x = int(p_raw), int(c1_raw), int(c2_raw), int(x_raw)  # type: ignore[arg-type]
    s = pow(c1, x, p)
    m = (c2 * modinv(s, p)) % p
    out = [Candidate(blob, f"elgamal[x={x}]: m = c2 * (c1^x)^-1") for _, blob in candidate_texts(m)]
    # Some authors encrypt the flag in small chunks; try splitting the integer
    raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
    if b"\x00" not in raw and len(raw) > 8:
        out.append(Candidate(raw, "elgamal: raw big-endian"))
    return out


def solve_hill(ctx: SolveContext) -> list[Candidate]:
    """Hill cipher with the key matrix present in the source, or recovered from a crib."""
    ct_text = _ciphertext_text(ctx)
    if not ct_text:
        return []
    matrices = _matrices(ctx.source_text)
    out: list[Candidate] = []
    for k, mname in matrices:
        dec = _hill_decrypt(ct_text, k)
        if not dec:
            continue
        # Hill output has no braces at all: keep only the restored flag form,
        # the raw concatenation is never the accepted answer.
        nodec = ctx.wrap_inline(dec, f"hill[{mname}]")
        if nodec:
            out.append(nodec)
    return out


def _ciphertext_text(ctx: SolveContext) -> str:
    m = re.search(r"ciphertext\s*[=:]\s*([A-Za-z]+)", ctx.output_text)
    if m:
        return m.group(1)
    cleaned = re.sub(r"[^A-Za-z]", "", ctx.output_text)
    return cleaned if len(cleaned) >= 4 else ""


def _matrices(source: str) -> list[tuple[list[list[int]], str]]:
    """Every square integer matrix literal in the script, with its variable name."""
    found: list[tuple[list[list[int]], str]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return found
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        label = next((t.id for t in node.targets if isinstance(t, ast.Name)), "K")
        value = node.value
        if not isinstance(value, (ast.List, ast.Tuple)) or not value.elts:
            continue
        rows: list[list[int]] = []
        ok = True
        for elt in value.elts:
            if not isinstance(elt, (ast.List, ast.Tuple)):
                ok = False
                break
            row: list[int] = []
            for sub in elt.elts:
                if isinstance(sub, ast.Constant) and isinstance(sub.value, int):
                    row.append(sub.value)
                else:
                    ok = False
                    break
            if not ok:
                break
            rows.append(row)
        if ok and rows and all(len(r) == len(rows) for r in rows) and 2 <= len(rows) <= 6:
            found.append((rows, label))
    return found


def _hill_decrypt(text: str, key: list[list[int]]) -> str | None:
    n = len(key)
    det = _det(key) % 26
    try:
        det_inv = modinv(det, 26)
    except ValueError:
        return None
    inv = _inverse_matrix(key, det_inv)
    letters = [c.lower() for c in text if c.isalpha()]
    if len(letters) % n:
        letters += ["x"] * (n - len(letters) % n)
    out: list[str] = []
    for i in range(0, len(letters), n):
        vec = [ord(c) - 97 for c in letters[i:i + n]]
        for r in range(n):
            s = sum(inv[r][c] * vec[c] for c in range(n)) % 26
            out.append(chr(s + 97))
    return "".join(out)


def _det(m: list[list[int]]) -> int:
    n = len(m)
    if n == 1:
        return m[0][0]
    if n == 2:
        return m[0][0] * m[1][1] - m[0][1] * m[1][0]
    total = 0
    for c in range(n):
        minor = [row[:c] + row[c + 1:] for row in m[1:]]
        total += ((-1) ** c) * m[0][c] * _det(minor)
    return total


def _inverse_matrix(m: list[list[int]], det_inv: int) -> list[list[int]]:
    n = len(m)
    cof = [[0] * n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            minor = [[m[i][j] for j in range(n) if j != c] for i in range(n) if i != r]
            cof[c][r] = ((-1) ** (r + c)) * _det(minor) if n > 1 else 1
    return [[(det_inv * cof[r][c]) % 26 for c in range(n)] for r in range(n)]


SOLVERS = {
    "dh_shared_secret": solve_dh,
    "elgamal_recover": solve_elgamal,
    "hill_matrix_inverse": solve_hill,
}