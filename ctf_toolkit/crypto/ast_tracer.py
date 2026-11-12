"""Static tracer for CTF challenge sources.

Parses an author-supplied generator script (`chall.py`, `server.py`, `enc.py`)
and recovers two things without executing it:

1.  Cipher family and mode, from the operations present in the AST.
2.  Role bindings (n / e / c / p / q / key / iv) from data-flow, not from
    variable spelling, so `zz = pp * qq` binds the same way `n = p * q` does.

`infer_params()` then crosses the source against the challenge output file so
that values are assigned to roles by arithmetic identity (`p * q == n`) rather
than by the label the author happened to print. When the identity check cannot
fire, a magnitude ranking is used and the result is marked unverified.

Nothing here executes untrusted code.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Role vocabulary
# ---------------------------------------------------------------------------

ROLE_ALIASES: dict[str, set[str]] = {
    "n": {"n", "nn", "mod", "modulus", "nb", "nbits", "pub_n"},
    "e": {"e", "ee", "exp", "exponent", "pub_e", "ex"},
    "c": {"c", "cc", "ct", "ciphertext", "enc", "encrypted", "c_msg", "cipher", "cval", "c_bytes"},
    "p": {"p", "pp", "prime1", "prime_p", "fact1"},
    "q": {"q", "qq", "prime2", "prime_q", "fact2"},
    "r": {"r", "rr", "prime3"},
    "d": {"d", "dd", "priv", "privkey", "private", "priv_d"},
    "phi": {"phi", "ph", "totient", "euler"},
    "key": {"key", "k", "secret", "key_byte", "kunci", "mask", "xor_key", "stream_key"},
    "iv": {"iv", "nonce", "salt", "seed_iv"},
    "g": {"g", "gg", "generator", "base_point"},
    "x": {"x", "priv_x", "secret_x", "alice", "bob", "d_priv"},
}

PAIR_CATEGORIES = {"p", "q", "r"}

# Signals: (category, weight, matcher)
# Weight is a confidence prior, not a probability. Multiple weak hits accumulate.

CATEGORY_PRIORS: dict[str, float] = {
    "rsa": 1.00,
    "dh": 0.95,
    "elgamal": 0.95,
    "ecc": 0.95,
    "aes": 0.90,
    "stream_cipher": 0.90,
    "xor": 0.85,
    "affine": 0.80,
    "hill": 0.80,
    "prng": 0.75,
    "otp": 0.70,
    "hash": 0.60,
    "encoding": 0.50,
    "classical": 0.55,
}


@dataclass
class TraceSignal:
    category: str
    weight: float
    evidence: str
    lineno: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "weight": round(self.weight, 3),
            "evidence": self.evidence,
            "line": self.lineno,
        }


@dataclass
class ChallengeTrace:
    source_name: str
    source: str
    categories: dict[str, float] = field(default_factory=dict)
    signals: list[TraceSignal] = field(default_factory=list)
    params: dict[str, int] = field(default_factory=dict)
    roles: dict[str, str] = field(default_factory=dict)
    helper_funcs: list[str] = field(default_factory=list)
    encodings: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    attack_plan: list[str] = field(default_factory=list)
    parse_error: str | None = None

    @property
    def primary(self) -> str:
        if not self.categories:
            return "unknown"
        return max(self.categories.items(), key=lambda kv: kv[1])[0]

    @property
    def confidence(self) -> float:
        if not self.categories:
            return 0.0
        top = max(self.categories.values())
        total = sum(self.categories.values())
        margin = top / total if total else 0.0
        return round(min(1.0, self.categories[self.primary] / 2.0) * margin, 3)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_name,
            "primary_category": self.primary,
            "confidence": self.confidence,
            "categories": {k: round(v, 3) for k, v in sorted(self.categories.items(), key=lambda kv: -kv[1])},
            "signals": [s.as_dict() for s in self.signals],
            "roles": self.roles,
            "params": {k: (str(v) if abs(v) > 10 ** 12 else v) for k, v in self.params.items()},
            "encodings": self.encodings,
            "imports": self.imports,
            "attack_plan": self.attack_plan,
            "parse_error": self.parse_error,
        }


# ---------------------------------------------------------------------------
# Literal evaluation (no execution)
# ---------------------------------------------------------------------------

def _const_int(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _const_int(node.operand)
        return -inner if inner is not None else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Pow, ast.LShift, ast.BitOr)):
        left, right = _const_int(node.left), _const_int(node.right)
        if left is None or right is None:
            return None
        try:
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.LShift):
                return left << right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if right > 4096:
                return None
            return left ** right
        except (OverflowError, ValueError):
            return None
    return None


def _target_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            names.extend(_target_names(elt))
    elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        names.append(node.value.id)
    return names


def _role_of(name: str) -> str | None:
    lowered = name.lower()
    for role, aliases in ROLE_ALIASES.items():
        if lowered in aliases:
            return role
    return None


# ---------------------------------------------------------------------------
# AST walkers
# ---------------------------------------------------------------------------

_MODERN_CIPHER_ATTRS = {
    "AES": "aes",
    "DES": "stream_cipher",
    "DES3": "stream_cipher",
    "ChaCha20": "stream_cipher",
    "Salsa20": "stream_cipher",
    "ARC4": "stream_cipher",
    "RC4": "stream_cipher",
    "Blowfish": "stream_cipher",
    "Fernet": "stream_cipher",
}

_MODE_NAMES = {"ECB", "CBC", "CTR", "CFB", "OFB", "GCM", "CCM", "EAX", "SIV", "XTS"}


class _Collector(ast.NodeVisitor):
    def __init__(self, trace: ChallengeTrace) -> None:
        self.t = trace
        self.assignments: dict[str, ast.AST] = {}
        self.assign_lineno: dict[str, int] = {}
        self.func_params: dict[str, list[str]] = {}
        self.calls: list[ast.Call] = []

    # -- helpers ---------------------------------------------------------
    def hit(self, category: str, weight: float, evidence: str, lineno: int) -> None:
        self.t.signals.append(TraceSignal(category, weight, evidence, lineno))
        self.t.categories[category] = self.t.categories.get(category, 0.0) + weight * CATEGORY_PRIORS.get(category, 0.5)

    def bind_role(self, name: str, lineno: int) -> None:
        role = _role_of(name)
        if role and role not in self.t.roles:
            self.t.roles[role] = name

    # -- nodes -----------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.t.imports.append(alias.name)
            self._import_signal(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        self.t.imports.append(mod)
        self._import_signal(mod, node.lineno)
        for alias in node.names:
            self._import_signal(f"{mod}.{alias.name}", node.lineno)
        self.generic_visit(node)

    def _import_signal(self, dotted: str, lineno: int) -> None:
        low = dotted.lower()
        if "cryptodome" in low or low.startswith("crypto") or ".cipher" in low:
            if low.endswith("aes") or ".aes" in low:
                self.hit("aes", 0.9, f"import {dotted}", lineno)
            elif any(x in low for x in ("chacha", "salsa", "arc4", "des", "blowfish")):
                self.hit("stream_cipher", 0.8, f"import {dotted}", lineno)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.t.helper_funcs.append(node.name)
        self.func_params[node.name] = [a.arg for a in node.args.args]
        # A function whose body is a single return of an arithmetic expression
        # is a transform; inspect its operators for cipher fingerprints.
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        value = node.value
        # constant folding into params
        const = _const_int(value)
        if const is not None:
            for name in _target_names(node.targets[0] if node.targets else node):
                self.assignments[name] = value
                self.assign_lineno[name] = node.lineno
                self.bind_role(name, node.lineno)
                if abs(const) > 0:
                    self.t.params[name] = const

        # n = p * q  /  n = pp * qq
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mult):
            left = _target_names(value.left)
            right = _target_names(value.right)
            lrole = _role_of(left[0]) if left else None
            rrole = _role_of(right[0]) if right else None
            if lrole in PAIR_CATEGORIES and rrole in PAIR_CATEGORIES and lrole != rrole:
                for name in _target_names(node.targets[0]):
                    if name not in self.t.roles:
                        self.t.roles["n"] = name
                self.hit("rsa", 1.0, f"{left[0]} * {right[0]} -> {self.t.roles.get('n')}", node.lineno)

        # phi = (p-1)*(q-1)
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mult):
            if any(isinstance(side, ast.BinOp) and isinstance(side.op, ast.Sub) for side in (value.left, value.right)):
                for name in _target_names(node.targets[0]):
                    self.t.roles.setdefault("phi", name)
                self.hit("rsa", 0.8, "totient construction (p-1)*(q-1)", node.lineno)

        # LCG: state = (a * state + b) % m
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod):
            inner = value.left
            if isinstance(inner, ast.BinOp) and isinstance(inner.op, (ast.Add, ast.Mult)):
                self.hit("prng", 0.7, "LCG recurrence (a*x+b) % m", node.lineno)

        # matrix built from nested list comprehension
        if isinstance(value, ast.ListComp):
            self._scan_expr(value.elt, node.lineno, in_comp=True)

        for name in _target_names(node.targets[0] if node.targets else ast.Name(id="")):
            self.bind_role(name, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        fname = ""
        if isinstance(node.func, ast.Name):
            fname = node.func.id
        elif isinstance(node.func, ast.Attribute):
            fname = node.func.attr
            if isinstance(node.func.value, ast.Name):
                fname = f"{node.func.value.id}.{node.func.attr}"

        low = fname.lower()

        # pow(base, exp, mod) -> RSA
        if low.split(".")[-1] == "pow" and len(node.args) >= 3:
            base = _target_names(node.args[0])
            exp = _target_names(node.args[1])
            mod = _target_names(node.args[2])
            exp_const = _const_int(node.args[1])
            if exp_const is not None:
                self.t.params.setdefault("e", exp_const)
                self.t.roles.setdefault("e", str(exp_const))
            if exp:
                self.bind_role(exp[0], node.lineno)
                self.t.roles.setdefault("e", exp[0])
            if mod:
                self.t.roles.setdefault("n", mod[0])
            if base:
                self.t.roles.setdefault("base", base[0])
            self.hit("rsa" if not self._looks_like_dh(node) else "dh", 1.0,
                     f"pow({base[0] if base else '?'}, {exp[0] if exp else exp_const if exp_const is not None else '?'}, {mod[0] if mod else '?'})", node.lineno)

        # Modern cipher constructors
        for attr, cat in _MODERN_CIPHER_ATTRS.items():
            if attr.lower() in low:
                self.hit(cat, 0.9, f"{fname}(...)", node.lineno)
                if attr == "AES" and len(node.args) >= 2:
                    mode_node = node.args[1]
                    mode_name = ""
                    if isinstance(mode_node, ast.Attribute):
                        mode_name = mode_node.attr
                    elif isinstance(mode_node, ast.Name):
                        mode_name = mode_node.id
                    mode_name = mode_name.upper().removeprefix("MODE_")
                    if mode_name in _MODE_NAMES:
                        self.t.encodings.append(f"aes-{mode_name}")
                break

        if low.endswith("getrandbits") or low.endswith("randint") or low.endswith("randrange") or low.endswith("choice") and "random" in low:
            self.hit("prng", 0.6, f"{fname}(...)", node.lineno)
        # Hand-rolled generators declared as a function call in the script
        for marker, cat in (
            ("rc4", "stream_cipher"), ("xorshift", "prng"), ("mt19937", "prng"),
            ("mersenne", "prng"), ("lcg", "prng"), ("aes_encrypt", "aes"),
            ("aes_decrypt", "aes"), ("chacha", "stream_cipher"), ("salsa", "stream_cipher"),
            ("hill", "hill"), ("elgamal", "elgamal"), ("vigenere", "classical"),
            ("affine", "affine"), ("rail", "classical"),
        ):
            if marker in low:
                self.hit(cat, 0.7, f"call {fname}", node.lineno)
        if low.endswith("urandom") or low.endswith("token_bytes") or low.endswith("token_hex"):
            self.t.encodings.append("os-random-bytes")
        if low.endswith("b64encode") or low.endswith("standard_b64encode"):
            self.t.encodings.append("base64")
            self.hit("encoding", 0.5, fname, node.lineno)
        if low.endswith("b32encode"):
            self.t.encodings.append("base32")
        if low.endswith("b85encode"):
            self.t.encodings.append("base85")
        if low.endswith("hexlify") or low.endswith("hex"):
            self.t.encodings.append("hex")
        if low.endswith("fromhex"):
            self.t.encodings.append("hex")
        if low.endswith("long_to_bytes") or low.endswith("int_to_bytes"):
            self.t.encodings.append("int->bytes")
        if low.endswith("bytes_to_long"):
            self.t.encodings.append("bytes->int")
        if low.endswith("md5") or low.endswith("sha1") or low.endswith("sha256") or low.endswith("sha512"):
            self.hit("hash", 0.6, fname, node.lineno)

        self._scan_expr(node, node.lineno)
        self.generic_visit(node)

    def _looks_like_dh(self, node: ast.Call) -> bool:
        """A 3-arg pow with a small-ish literal exponent and small literal base reads as DH."""
        if len(node.args) < 3:
            return False
        base = _const_int(node.args[0])
        exp = _const_int(node.args[1])
        if base is not None and base < 10 and exp is not None and exp < 10 ** 4:
            return True
        return False

    def _scan_expr(self, node: ast.AST, lineno: int, in_comp: bool = False) -> None:
        for sub in ast.walk(node):
            if isinstance(sub, ast.BinOp):
                if isinstance(sub.op, ast.BitXor):
                    self.hit("xor", 0.8, "bitwise XOR in expression", getattr(sub, "lineno", lineno))
                elif isinstance(sub.op, ast.MatMult):
                    self.hit("hill", 0.9, "matrix multiplication", getattr(sub, "lineno", lineno))
            # (a * ch + b) % 26 style affine transform
            if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Mod):
                right = _const_int(sub.right)
                if right == 26:
                    self.hit("affine", 0.7, "mod 26 affine transform", getattr(sub, "lineno", lineno))
                elif right == 256:
                    self.hit("xor", 0.3, "mod 256 byte transform", getattr(sub, "lineno", lineno))
            if isinstance(sub, ast.Call):
                fn = sub.func
                if isinstance(fn, ast.Name) and fn.id == "ord":
                    self.hit("classical", 0.3, "ord() arithmetic transform", getattr(sub, "lineno", lineno))
            if isinstance(sub, ast.ListComp) or isinstance(sub, ast.GeneratorExp):
                elt = sub.elt
                if isinstance(elt, ast.BinOp) and isinstance(elt.op, ast.Mult):
                    self.hit("hill", 0.6, "nested comprehension product", getattr(sub, "lineno", lineno))


def _category_specifics(tree: ast.AST, trace: ChallengeTrace) -> None:
    """Second pass for patterns that need structural (not node-local) context."""
    src_dump = ast.dump(tree)

    # DH: two pow() calls sharing a modulus variable
    pow_mods: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and len(node.args) == 3:
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else "")
            if name == "pow":
                mods = _target_names(node.args[2])
                if mods:
                    pow_mods.append(mods[0])
    if len(pow_mods) >= 2 and len(set(pow_mods)) == 1:
        trace.categories["dh"] = trace.categories.get("dh", 0.0) + 0.9
        trace.signals.append(TraceSignal("dh", 0.9, f"shared modulus across {len(pow_mods)} pow() calls", 0))

    # ElGamal: ciphertext pair (c1, c2)
    if "c1" in src_dump.lower() and "c2" in src_dump.lower():
        trace.categories["elgamal"] = trace.categories.get("elgamal", 0.0) + 0.7
        trace.signals.append(TraceSignal("elgamal", 0.7, "ciphertext pair (c1, c2)", 0))

    # RSA key generation markers
    if "getPrime" in src_dump or "getprime" in src_dump.lower():
        trace.categories["rsa"] = trace.categories.get("rsa", 0.0) + 0.8
        trace.signals.append(TraceSignal("rsa", 0.8, "prime generation (getPrime)", 0))

    # ECC markers
    for marker in ("EllipticCurve", "scalar_mult", "point_add", "ECDSASignature"):
        if marker in src_dump:
            trace.categories["ecc"] = trace.categories.get("ecc", 0.0) + 0.8
            trace.signals.append(TraceSignal("ecc", 0.8, marker, 0))
            break


def trace_source(source: str, source_name: str = "<memory>") -> ChallengeTrace:
    """Parse and classify a generator script. Never executes it."""
    trace = ChallengeTrace(source_name=source_name, source=source)
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        trace.parse_error = f"{exc.msg} (line {exc.lineno})"
        _regex_fallback(source, trace)
        _finalize(trace)
        return trace

    collector = _Collector(trace)
    collector.visit(tree)
    _category_specifics(tree, trace)

    # Fold constants declared anywhere (assignments inside functions too)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            const = _const_int(node.value)
            if const is None:
                continue
            for name in _target_names(node.targets[0]):
                trace.params.setdefault(name, const)

    _finalize(trace)
    return trace


def _regex_fallback(source: str, trace: ChallengeTrace) -> None:
    """Python-2 or otherwise unparsable source: degrade to lexical fingerprinting."""
    low = source.lower()
    table = [
        ("rsa", ("pow(", "getprime", "inverse(", "phi", "modulus")),
        ("aes", ("aes.new", "from crypto.cipher import aes", "ciphertext")),
        ("xor", ("^", "xor")),
        ("dh", ("pow(g", "shared")),
        ("prng", ("random", "getrandbits", "seed(")),
        ("encoding", ("b64encode", "hexlify", "b32encode")),
    ]
    for cat, needles in table:
        hits = [n for n in needles if n in low]
        if hits:
            trace.categories[cat] = trace.categories.get(cat, 0.0) + 0.5 * len(hits)
            trace.signals.append(TraceSignal(cat, 0.5, "lexical: " + ", ".join(hits), 0))
    for m in re.finditer(r"([A-Za-z_]\w*)\s*=\s*(\d{2,})", source):
        try:
            trace.params.setdefault(m.group(1), int(m.group(2)))
        except ValueError:
            continue


def _finalize(trace: ChallengeTrace) -> None:
    seen: set[str] = set()
    uniq: list[str] = []
    for enc in trace.encodings:
        if enc not in seen:
            seen.add(enc)
            uniq.append(enc)
    trace.encodings = uniq
    trace.attack_plan = plan_from(trace)


def trace_file(path: str | Path) -> ChallengeTrace:
    p = Path(path)
    return trace_source(p.read_text(encoding="utf-8", errors="replace"), source_name=p.name)


# ---------------------------------------------------------------------------
# Output-file parsing: values without trusting labels
# ---------------------------------------------------------------------------

_INT_LINE = re.compile(r"(?P<label>[A-Za-z_][A-Za-z0-9_]{0,31})?\s*[=:]\s*(?P<val>0[xX][0-9a-fA-F]+|\d{1,})")
_BARE_HEX = re.compile(r"(?<![0-9a-zA-Z])0[xX][0-9a-fA-F]{8,}")
_BARE_INT = re.compile(r"(?<![0-9a-zA-Z_.])(\d{6,})(?![0-9a-zA-Z_.])")


@dataclass
class NumericBlob:
    label: str | None
    value: int
    raw: str
    source: str  # 'labeled' | 'bare' | 'hex'

    def as_dict(self) -> dict[str, Any]:
        return {"label": self.label, "bits": self.value.bit_length(), "source": self.source,
                "preview": self.raw[:24] + ("..." if len(self.raw) > 24 else "")}


def extract_numeric_blobs(text: str) -> list[NumericBlob]:
    """Every integer of interest in a challenge output, labelled or not."""
    blobs: list[NumericBlob] = []
    seen: set[int] = set()

    for m in _INT_LINE.finditer(text):
        raw = m.group("val")
        try:
            val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
        except ValueError:
            continue
        if val in seen:
            continue
        seen.add(val)
        blobs.append(NumericBlob(m.group("label"), val, raw, "labeled"))

    for m in _BARE_HEX.finditer(text):
        val = int(m.group(0), 16)
        if val in seen:
            continue
        seen.add(val)
        blobs.append(NumericBlob(None, val, m.group(0), "hex"))

    for m in _BARE_INT.finditer(text):
        val = int(m.group(1))
        if val in seen:
            continue
        seen.add(val)
        blobs.append(NumericBlob(None, val, m.group(1), "bare"))

    blobs.sort(key=lambda b: -b.value)
    return blobs


def extract_int_list(text: str) -> list[int]:
    """Parse `[a, b, c]` / space separated integers used by stream and matrix challenges."""
    for m in re.finditer(r"\[([^\[\]]{10,})\]", text):
        parts = re.findall(r"-?\d+", m.group(1))
        if len(parts) >= 4:
            return [int(p) for p in parts]
    parts = re.findall(r"(?<!\d)(\d{1,4})(?!\d)", text)
    if len(parts) >= 16:
        return [int(p) for p in parts]
    return []


def extract_bytes_constants(source: str) -> list[tuple[str | None, bytes]]:
    """Byte-string literals and `bytes([...])` / `fromhex(...)` calls in a script.

    Used when the challenge embeds its own key, which is the common case for
    training-tier AES/XOR tasks: the solver does not need to break anything,
    it needs to recover the constant and the mode boundary.
    """
    out: list[tuple[str | None, bytes]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        for m in re.finditer(r"([A-Za-z_]\w*)\s*=\s*bytes\(\[([0-9,\s]+)\]\)", source):
            try:
                out.append((m.group(1), bytes(int(x) for x in m.group(2).split(",") if x.strip())))
            except ValueError:
                continue
        for m in re.finditer(r"bytes\.fromhex\(\s*[\"']([0-9a-fA-F]+)[\"']\s*\)", source):
            out.append((None, bytes.fromhex(m.group(1))))
        return out

    # name -> bytes, for assignments
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        label = next((t.id for t in node.targets if isinstance(t, ast.Name)), None)
        value = node.value
        blob: bytes | None = None
        if isinstance(value, ast.Constant) and isinstance(value.value, bytes):
            blob = value.value
        elif isinstance(value, ast.Constant) and isinstance(value.value, str):
            # Plain string constants are keys too ("lemon", "night").
            if 1 <= len(value.value) <= 64:
                blob = value.value.encode("latin-1", "ignore")
        elif isinstance(value, ast.Call):
            fn = value.func
            fname = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
            if fname == "bytes" and value.args:
                arg = value.args[0]
                if isinstance(arg, (ast.List, ast.Tuple)):
                    vals = [_const_int(e) for e in arg.elts]
                    if all(v is not None and 0 <= v < 256 for v in vals):
                        blob = bytes(v for v in vals if v is not None)
                elif isinstance(arg, ast.Call):
                    fn2 = arg.func
                    fn2_name = fn2.id if isinstance(fn2, ast.Name) else ""
                    if fn2_name == "range" and arg.args:
                        r_end = _const_int(arg.args[0]) if len(arg.args) == 1 else (_const_int(arg.args[1]) if len(arg.args) >= 2 else None)
                        r_start = _const_int(arg.args[0]) if len(arg.args) >= 2 else 0
                        if r_start is not None and r_end is not None and 0 <= r_start <= r_end <= 256:
                            blob = bytes(range(r_start, r_end))
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    blob = arg.value.encode("latin-1", "ignore")
            elif fname == "fromhex" and value.args:
                arg = value.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    try:
                        blob = bytes.fromhex(arg.value)
                    except ValueError:
                        blob = None
            elif fname == "unhexlify" and value.args:
                arg = value.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    try:
                        blob = bytes.fromhex(arg.value)
                    except ValueError:
                        blob = None
        if blob and len(blob) >= 1:
            out.append((label, blob))
    return out


# ---------------------------------------------------------------------------
# Role resolution
# ---------------------------------------------------------------------------

def _assign_by_identity(values: list[int], params: dict[str, int]) -> None:
    """Fill p/q when a factor pair of n is present in the output."""
    n = params.get("n")
    if n is None:
        return
    candidates = [v for v in values if 1 < v < n and n % v == 0]
    if len(candidates) >= 2:
        candidates.sort()
        p, q = candidates[0], n // candidates[0]
        if p * q == n:
            params["p"], params["q"] = p, q


def _assign_by_magnitude(values: list[int], params: dict[str, int]) -> list[str]:
    """Fallback layout: biggest -> n, next -> c, small odd -> e. Returns notes."""
    notes: list[str] = []
    ranked = sorted(set(values), reverse=True)
    if "n" not in params and ranked:
        params["n"] = ranked[0]
        notes.append("n chosen as largest integer (magnitude heuristic)")
    if "c" not in params:
        rest = [v for v in ranked if v != params.get("n")]
        if rest:
            params["c"] = rest[0]
            notes.append("c chosen as second-largest integer (magnitude heuristic)")
    if "e" not in params:
        small = [v for v in ranked if 1 < v < 2 ** 32 and v % 2 == 1 and v != params.get("n") and v != params.get("c")]
        if small:
            params["e"] = 65537 if 65537 in small else small[0]
            notes.append("e chosen from small odd integers (magnitude heuristic)")
    return notes


def infer_params(
    trace: ChallengeTrace | None,
    output_text: str = "",
    supplied: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Resolve n/e/c/p/q/d/phi by source role names first, arithmetic identity second."""
    params: dict[str, int] = dict(supplied or {})
    notes: list[str] = []
    verified: list[str] = []

    blobs = extract_numeric_blobs(output_text) if output_text else []
    values = [b.value for b in blobs]
    by_label = {b.label.lower(): b.value for b in blobs if b.label}

    # 1. Source-declared role names map onto output labels of the same name.
    if trace:
        for role, var in trace.roles.items():
            if role in params:
                continue
            if var.lower() in by_label:
                params[role] = by_label[var.lower()]
                notes.append(f"{role} <- output label '{var}'")

    # 2. Output labels that happen to be canonical role names.
    for role, aliases in ROLE_ALIASES.items():
        if role in params:
            continue
        for alias, val in by_label.items():
            if alias in aliases:
                params[role] = val
                notes.append(f"{role} <- output label '{alias}'")
                break

    # 2b. Carry every remaining short label through verbatim so solvers can read
    #     author-chosen names like c1 / c2 / A / B / nonce without a role table.
    for label, val in by_label.items():
        if label in params or label in ("n", "e", "c", "p", "q", "r", "d", "phi"):
            continue
        if len(label) <= 16 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", label):
            params.setdefault(label, val)

    # 3. Magnitude fallback for anything still missing.
    if "n" not in params or "c" not in params:
        notes.extend(_assign_by_magnitude(values, params))

    # 4. Identity verification / repair.
    if "n" in params and "p" in params and "q" in params:
        if params["p"] * params["q"] == params["n"]:
            verified.append("p*q == n")
        else:
            params.pop("p", None)
            params.pop("q", None)
            notes.append("p*q != n, dropped unverified factors")
    if "p" not in params:
        _assign_by_identity(values, params)
        if "p" in params:
            verified.append("p*q == n (recovered from outputs)")

    # 5. e sanity: RSA public exponents are coprime to phi and usually small.
    if "e" in params and "p" in params and "q" in params:
        from math import gcd
        phi = (params["p"] - 1) * (params["q"] - 1)
        if gcd(params["e"], phi) != 1:
            notes.append(f"e={params['e']} shares factor with phi; likely misassigned")
            params.pop("e", None)

    # 6. c must be smaller than n; drop and re-pick the largest remaining candidate.
    if "c" in params and "n" in params and params["c"] >= params["n"]:
        dropped = params.pop("c")
        rest = [v for v in values if v < params["n"] and v != params.get("e")]
        if rest:
            params["c"] = max(rest)
            notes.append(f"c reassigned: {dropped.bit_length()} bits >= n, picked largest value < n")

    return {
        "params": params,
        "notes": notes,
        "verified": verified,
        "blobs": [b.as_dict() for b in blobs[:20]],
        "roles": trace.roles if trace else {},
    }


# ---------------------------------------------------------------------------
# Attack planning
# ---------------------------------------------------------------------------

def plan_from(trace: ChallengeTrace | None = None, params: dict[str, int] | None = None) -> list[str]:
    """Ordered solver ladder: precise family first, then generic structural sweeps."""
    plan: list[str] = []
    cats = trace.categories if trace else {}
    p: dict[str, int] = {}
    if trace and trace.params:
        p.update(trace.params)
    p.update(params or {})

    def add(*items: str) -> None:
        for it in items:
            if it not in plan:
                plan.append(it)

    # Precision families ordered by their own confidence, not by a fixed ladder
    ordered = [c for c, _ in sorted(cats.items(), key=lambda kv: -kv[1])]
    for cat in ordered:
        if cat == "elgamal":
            add("elgamal_recover")
        elif cat == "dh":
            add("dh_shared_secret")
        elif cat == "hill":
            add("hill_matrix_inverse")
        elif cat == "stream_cipher":
            add("stream_known_key", "stream_keystream_reuse")
        elif cat == "prng":
            add("prng_mt_clone", "prng_lcg_solve")
        elif cat == "xor":
            add("xor_single_byte", "xor_repeating_key")
        elif cat == "affine":
            add("affine_bruteforce")
        elif cat == "aes":
            add("aes_known_key", "aes_ecb_oracle")
        elif cat == "encoding":
            add("encoding_peel")
        elif cat == "classical":
            add("vigenere_ic_break", "caesar_bruteforce", "railfence_bruteforce")
        elif cat == "hash":
            add("hash_lookup")

    # RSA ladder only when RSA is actually signalled or its parameters exist
    if "rsa" in cats or {"n", "c"} <= set(p):
        if {"p", "q", "e", "c"} <= set(p):
            add("rsa_given_factors")
        if "phi" in p and {"n", "e", "c"} <= set(p):
            add("rsa_phi_leak")
        if p.get("e", 65537) <= 11:
            add("rsa_small_e_root")
        add("rsa_shared_prime", "rsa_small_factor_trial", "rsa_fermat")
        if p.get("e", 0) and p.get("n") and p["e"].bit_length() > p["n"].bit_length() // 2:
            add("rsa_wiener")
        add("rsa_pollard_pm1", "rsa_factor_auto")

    if not cats:
        add("encoding_peel", "caesar_bruteforce", "affine_bruteforce",
            "vigenere_ic_break", "railfence_bruteforce")
    add("hash_lookup", "flag_pattern_scan")
    return plan


# ---------------------------------------------------------------------------
# Convenience: whole-directory tracing
# ---------------------------------------------------------------------------

_SOURCE_SUFFIXES = {".py", ".sage", ".txt", ".py2"}
_OUTPUT_HINTS = ("output", "out", "enc", "cipher", "ct", "data", "dist")


def trace_directory(path: str | Path) -> dict[str, Any]:
    """Pick the generator script and its output file out of a challenge folder."""
    root = Path(path)
    scripts = [p for p in root.iterdir() if p.suffix in {".py", ".sage"}] if root.is_dir() else []
    scripts = [p for p in scripts if "solve" not in p.name.lower()]
    outputs = [p for p in root.iterdir() if p.is_file() and p not in scripts] if root.is_dir() else []

    trace: ChallengeTrace | None = None
    if scripts:
        scripts.sort(key=lambda p: (0 if p.name in ("chall.py", "challenge.py", "server.py", "enc.py") else 1, p.name))
        trace = trace_file(scripts[0])

    out_text = ""
    chosen = None
    ranked = sorted(
        [p for p in outputs if p.suffix in {".txt", ".out", ".json", ".dat", ".bin", ".enc"} or any(h in p.name.lower() for h in _OUTPUT_HINTS)],
        key=lambda p: (0 if p.name.lower().startswith("output") else 1, -p.stat().st_size if p.stat().st_size < 2_000_000 else 0, p.name),
    )
    if ranked:
        chosen = ranked[0]
        raw = chosen.read_bytes()
        try:
            out_text = raw.decode("utf-8")
        except UnicodeDecodeError:
            out_text = raw.decode("latin-1")

    resolved = infer_params(trace, out_text)
    report = {
        "directory": str(root),
        "script": trace.source_name if trace else None,
        "script_path": str(scripts[0]) if scripts else None,
        "output_file": chosen.name if chosen else None,
        "output_path": str(chosen) if chosen else None,
        "trace": trace.as_dict() if trace else None,
        "params": resolved["params"],
        "notes": resolved["notes"],
        "verified": resolved["verified"],
        "blobs": resolved["blobs"],
    }
    plan = plan_from(trace, resolved["params"])
    # Output-only evidence: when the script tells us little, the bytes do.
    report["signal"] = _signal_block(chosen)
    report["plan"] = _augment_plan(plan, report["signal"])
    return report


def _signal_block(path: Path | None) -> dict | None:
    if path is None:
        return None
    try:
        raw = path.read_bytes()[:8192]
    except OSError:
        return None
    if not raw:
        return None
    import base64
    import binascii
    import re

    from .signal import classify, describe

    families: dict[str, float] = {}
    for family, confidence in classify(raw):
        families[family] = max(families.get(family, 0.0), confidence)

    # If the surface is an encoding, judge the decoded payload instead of the ink.
    text = raw.decode("latin-1").strip()
    decoded: bytes | None = None
    if re.fullmatch(r"[0-9a-fA-F\s]+", text) and len(re.sub(r"\s", "", text)) % 2 == 0:
        try:
            decoded = bytes.fromhex(re.sub(r"\s", "", text))
        except ValueError:
            decoded = None
    elif re.fullmatch(r"[A-Za-z0-9+/\s]*={0,2}", text) and len(re.sub(r"\s", "", text)) % 4 == 0:
        try:
            decoded = base64.b64decode(re.sub(r"\s", "", text))
        except (binascii.Error, ValueError):
            decoded = None
    if decoded:
        for family, confidence in classify(decoded):
            families[family] = max(families.get(family, 0.0), confidence)

    # Stream generators: a long run of 32-bit integers is an MT19937 dump.
    ints = re.findall(r"\b\d{6,10}\b", text)
    if len(ints) >= 600 and all(int(v) < 2 ** 32 for v in ints[:600]):
        families["prng"] = max(families.get("prng", 0.0), 0.9)

    ranked = sorted(families.items(), key=lambda kv: -kv[1])
    return {"features": describe(raw), "families": ranked}


def _augment_plan(plan: list[str], signal: dict | None) -> list[str]:
    """Insert families the statistics support but the source never revealed."""
    if not signal:
        return plan
    from .signal import classify

    extra: list[str] = []
    for family, confidence in signal["families"]:
        if confidence < 0.6:
            continue
        if family == "encoding":
            extra.append("encoding_peel")
        elif family == "classical":
            extra.extend(["caesar_bruteforce", "vigenere_ic_break", "affine_bruteforce"])
        elif family == "xor":
            extra.extend(["xor_single_byte", "xor_repeating_key"])
        elif family == "stream_cipher":
            extra.extend(["stream_known_key", "stream_keystream_reuse"])
        elif family == "prng":
            extra.extend(["prng_mt_clone", "prng_lcg_solve"])
        elif family == "hill":
            extra.append("hill_matrix_inverse")
    merged = list(plan)
    insert_at = max(0, len(merged) - 2)  # keep hash/flag-scan last
    for name in extra:
        if name not in merged:
            merged.insert(insert_at, name)
            insert_at += 1
    return merged


def format_trace(report: dict[str, Any]) -> str:
    """Human-readable trace block for CLI output."""
    lines: list[str] = []
    tr = report.get("trace") or {}
    if tr:
        lines.append(f"source      : {tr.get('source')}")
        lines.append(f"category    : {tr.get('primary_category')} (confidence {tr.get('confidence')})")
        if tr.get("parse_error"):
            lines.append(f"parse error : {tr['parse_error']}")
        lines.append("signals     :")
        for s in (tr.get("signals") or [])[:12]:
            lines.append(f"  - [{s['category']}] {s['evidence']}  (line {s['line']})")
        if tr.get("roles"):
            lines.append("roles       : " + ", ".join(f"{k}={v}" for k, v in tr["roles"].items()))
    if report.get("output_file"):
        lines.append(f"output file : {report['output_file']}")
    if report.get("params"):
        lines.append("resolved    :")
        for k, v in report["params"].items():
            sv = str(v)
            lines.append(f"  {k} = {sv[:64]}{'...' if len(sv) > 64 else ''}  [{int(v).bit_length()} bits]")
    if report.get("verified"):
        lines.append("verified    : " + "; ".join(report["verified"]))
    if report.get("notes"):
        lines.append("notes       : " + "; ".join(report["notes"]))
    if report.get("plan"):
        lines.append("plan        : " + " -> ".join(report["plan"]))
    return "\n".join(lines)
