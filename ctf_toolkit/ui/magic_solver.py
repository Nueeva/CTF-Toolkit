from __future__ import annotations

import base64
import heapq
import re
import urllib.parse
import zlib
import gzip
from collections import Counter
from typing import Any

from ctf_toolkit.crypto.classical import atbash, rot_n
from ctf_toolkit.reversing.transforms import xor_bytes
from ctf_toolkit.ui.console import (
    HAS_RICH,
    get_rich_console,
    console_info,
    console_success,
    console_warn,
    console_error,
)
from ctf_toolkit.ui.inspector import calculate_shannon_entropy, inspect_output
from ctf_toolkit.ui.session import resolve_smart_input

try:
    from rich.tree import Tree
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
except ImportError:
    pass


def index_of_coincidence(data: bytes) -> float:
    """Calculate the Index of Coincidence (IC) for text bytes."""
    letters = [b for b in data if (65 <= b <= 90) or (97 <= b <= 122)]
    n = len(letters)
    if n <= 1:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def score_plaintext(data: bytes) -> float:
    """Evaluate fitness of candidate plaintext:
    - High bonus for CTF flag patterns
    - High bonus for high printable ASCII ratio
    - Bonus for English-like Index of Coincidence (~0.065)
    - Bonus for reasonable text entropy (3.5 - 5.2)
    """
    if not data:
        return -100.0

    # 1. CTF Flag check (Instant high score)
    flag_match = re.search(rb"(?:FLAG|CTF|GETSFLAG|LKS|picoCTF)\{[^\n\r\}]{3,100}\}", data, re.IGNORECASE)
    if flag_match:
        return 10000.0 + len(data)

    total = len(data)
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    printable_ratio = printable / total

    # If mostly binary gibberish, heavy penalty
    if printable_ratio < 0.70:
        return printable_ratio * 10.0

    score = printable_ratio * 100.0

    # 2. English letter frequency / Index of Coincidence
    ic = index_of_coincidence(data)
    if 0.050 <= ic <= 0.085:
        score += 50.0

    # 3. Shannon Entropy
    ent = calculate_shannon_entropy(data)
    if 3.5 <= ent <= 5.5:
        score += 30.0
    elif ent > 7.0:
        score -= 40.0

    # 4. Common English words bonus
    common_words = [b" the ", b" and ", b" that ", b" with ", b" this ", b" for "]
    data_lower = data.lower()
    for w in common_words:
        if w in data_lower:
            score += 20.0

    return score


def apply_step(op: str, data: bytes) -> bytes | None:
    """Safely apply a single cryptographic/encoding transformation."""
    try:
        if op == "b64d":
            # Strip whitespace
            clean = re.sub(rb"\s+", b"", data)
            if len(clean) % 4 != 0:
                clean += b"=" * (4 - len(clean) % 4)
            res = base64.b64decode(clean, validate=False)
            return res if res and res != data else None

        if op == "b32d":
            clean = re.sub(rb"\s+", b"", data).upper()
            if len(clean) % 8 != 0:
                clean += b"=" * (8 - len(clean) % 8)
            res = base64.b32decode(clean)
            return res if res and res != data else None

        if op == "hex_d":
            clean = re.sub(rb"\s+", b"", data)
            if re.match(rb"^[0-9a-fA-F]+$", clean) and len(clean) % 2 == 0:
                res = bytes.fromhex(clean.decode("ascii"))
                return res if res and res != data else None
            return None

        if op == "url_d":
            text = data.decode("latin1")
            unquoted = urllib.parse.unquote(text).encode("latin1")
            return unquoted if unquoted != data else None

        if op == "zlib_d":
            return zlib.decompress(data)

        if op == "gzip_d":
            return gzip.decompress(data)

        if op == "rot13":
            text = data.decode("latin1", errors="ignore")
            rotated = rot_n(text, 13).encode("latin1")
            return rotated if rotated != data else None

        if op == "atbash":
            text = data.decode("latin1", errors="ignore")
            res = atbash(text).encode("latin1")
            return res if res != data else None

        if op == "reverse":
            return data[::-1]

        if op.startswith("xor:"):
            key = int(op.split(":")[1], 16)
            return xor_bytes(data, key)

    except Exception:
        return None

    return None


CANDIDATE_OPS = [
    "b64d",
    "hex_d",
    "b32d",
    "url_d",
    "zlib_d",
    "gzip_d",
    "rot13",
    "atbash",
    "reverse",
]


def solve_magic(data: bytes, max_depth: int = 4, max_states: int = 150) -> tuple[bytes, list[str], float, list[dict]]:
    """A* Heuristic Tree Search to automatically crack layered encodings/ciphers:
    Returns (best_data, best_path, best_score, tree_history).
    """
    initial_score = score_plaintext(data)
    if initial_score >= 10000.0:
        return data, ["(direct)"], initial_score, []

    # Priority Queue stores (-score, depth, path, data)
    pq: list[tuple[float, int, list[str], bytes]] = []
    heapq.heappush(pq, (-initial_score, 0, [], data))

    visited: set[int] = {hash(data)}
    best_data = data
    best_path: list[str] = []
    best_score = initial_score

    tree_history: list[dict] = []
    states_count = 0

    while pq and states_count < max_states:
        neg_score, depth, path, current = heapq.heappop(pq)
        states_count += 1
        current_score = -neg_score

        if current_score > best_score:
            best_score = current_score
            best_data = current
            best_path = path

        # Found flag! Short-circuit search immediately
        if current_score >= 10000.0:
            break

        if depth >= max_depth:
            continue

        # Check candidate transforms
        ops_to_try = list(CANDIDATE_OPS)

        # Single-byte XOR candidate exploration
        if len(current) >= 4:
            scored_keys = []
            for k in range(1, 256):
                dec = xor_bytes(current, k)
                if re.search(rb"(?:FLAG|CTF|GETSFLAG|LKS)\{[^\n\r\}]{3,100}\}", dec, re.IGNORECASE):
                    ops_to_try.append(f"xor:0x{k:02x}")
                    break
                b64_cnt = sum(1 for b in dec if (65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) or b in (43, 47, 61))
                prn_cnt = sum(1 for b in dec if 32 <= b <= 126 or b in (9, 10, 13))
                s_k = (b64_cnt / len(dec)) * 60.0 + (prn_cnt / len(dec)) * 40.0
                scored_keys.append((s_k, k))
            scored_keys.sort(reverse=True)
            for _, k in scored_keys[:4]:
                op_k = f"xor:0x{k:02x}"
                if op_k not in ops_to_try:
                    ops_to_try.append(op_k)

        for op in ops_to_try:
            nxt = apply_step(op, current)
            if nxt is None or not nxt or len(nxt) < 2:
                continue

            h = hash(nxt)
            if h in visited:
                continue
            visited.add(h)

            s = score_plaintext(nxt)
            new_path = path + [op]
            tree_history.append({
                "depth": depth + 1,
                "op": op,
                "score": s,
                "preview": nxt[:24],
                "path": " -> ".join(new_path),
            })

            heapq.heappush(pq, (-s, depth + 1, new_path, nxt))

    return best_data, best_path, best_score, tree_history


def render_magic_tree(data: bytes, best_path: list[str], history: list[dict]) -> None:
    """Render rich tree visualization of decoding paths explored."""
    console = get_rich_console()
    if HAS_RICH and console:
        tree = Tree(f"⚡ [bold cyan]Magic Search Root[/bold cyan] [dim]({len(data)} bytes)[/dim]")
        
        # Group by first-level branches
        branches: dict[str, Any] = {}
        for entry in history:
            op_chain = entry["path"].split(" -> ")
            root_op = op_chain[0]
            if root_op not in branches:
                branches[root_op] = tree.add(f"[bold yellow]{root_op}[/bold yellow]")
            
            leaf_style = "bold green" if entry["score"] >= 10000.0 else "dim"
            flag_marker = " 🏆 [FLAG]" if entry["score"] >= 10000.0 else ""
            prev_str = repr(entry['preview'])[:20]
            branches[root_op].add(
                f"[{leaf_style}]{entry['path']}[/{leaf_style}] -> {prev_str} [dim](score: {entry['score']:.1f}){flag_marker}[/dim]"
            )
        console.print(Panel(tree, title="[bold bright_white]A* Heuristic Search Tree[/bold bright_white]", border_style="cyan"))
    else:
        print("\n--- A* Search Branches ---")
        for h in history[:15]:
            print(f"  [{h['depth']}] {h['path']} -> {repr(h['preview'])[:24]} (score: {h['score']:.1f})")


def magic_interactive() -> None:
    """Interactive CLI runner for the Autonomous Magic Solver."""
    print("\n=== 🔮 Autonomous Magic Solver (Ciphey / A* Engine) ===")
    raw = input("Masukkan ciphertext / payload ($last, @file, hex:, b64:, atau teks): ").strip()
    if not raw:
        console_warn("Input kosong.")
        return

    try:
        data = resolve_smart_input(raw, as_bytes=True)
    except Exception as e:
        console_error(f"Gagal memproses input: {e}")
        return

    console_info(f"Menganalisis payload ({len(data)} bytes)... mencari solusi multi-hop...")
    best_data, best_path, best_score, history = solve_magic(data)

    render_magic_tree(data, best_path, history)

    if best_path and best_path != ["(direct)"]:
        console_success(f"Solusi ditemukan via: [bold yellow]{' -> '.join(best_path)}[/bold yellow] (Score: {best_score:.1f})")
    else:
        console_info("Tidak ada transformasi multi-hop yang menghasilkan teks lebih baik.")

    inspect_output(best_data, title=f"Magic Result ({' -> '.join(best_path) if best_path else 'original'})", op_name="magic_solver")
