from __future__ import annotations

from Crypto.Hash import keccak


def _keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def hash_eip191_message(message: str | bytes) -> bytes:
    """Compute EIP-191 personal_sign hash: keccak256('\x19Ethereum Signed Message:\n' + len + msg)."""
    if isinstance(message, str):
        msg_bytes = message.encode("utf-8")
    else:
        msg_bytes = message
    prefix = f"\x19Ethereum Signed Message:\n{len(msg_bytes)}".encode("utf-8")
    return _keccak256(prefix + msg_bytes)


def compute_create2_address(
    deployer: str, salt: bytes | str, init_code_hash: bytes | str
) -> str:
    """Compute deterministic contract address deployed via CREATE2 opcode (EIP-1014)."""
    dep_clean = deployer.lower().replace("0x", "")
    dep_bytes = bytes.fromhex(dep_clean)

    if isinstance(salt, str):
        salt_clean = salt.lower().replace("0x", "")
        salt_bytes = bytes.fromhex(salt_clean.rjust(64, "0"))
    else:
        salt_bytes = salt.rjust(32, b"\x00")

    if isinstance(init_code_hash, str):
        init_clean = init_code_hash.lower().replace("0x", "")
        init_bytes = bytes.fromhex(init_clean.rjust(64, "0"))
    else:
        init_bytes = init_code_hash

    payload = b"\xff" + dep_bytes + salt_bytes + init_bytes
    h = _keccak256(payload)
    return "0x" + h[12:].hex()


def compute_create_address(sender: str, nonce: int) -> str:
    """Compute contract address created via CREATE opcode from sender and nonce."""
    sender_clean = sender.lower().replace("0x", "")
    sender_bytes = bytes.fromhex(sender_clean)

    # Simplified RLP encoding for [sender_bytes, nonce]
    # Sender is always 20 bytes -> 0x94 + sender_bytes
    rlp_sender = b"\x94" + sender_bytes

    if nonce == 0:
        rlp_nonce = b"\x80"
    elif nonce < 0x80:
        rlp_nonce = bytes([nonce])
    else:
        nonce_bytes = nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
        rlp_nonce = bytes([0x80 + len(nonce_bytes)]) + nonce_bytes

    payload_data = rlp_sender + rlp_nonce
    if len(payload_data) < 56:
        rlp_total = bytes([0xc0 + len(payload_data)]) + payload_data
    else:
        len_bytes = len(payload_data).to_bytes((len(payload_data).bit_length() + 7) // 8, "big")
        rlp_total = bytes([0xf7 + len(len_bytes)]) + len_bytes + payload_data

    h = _keccak256(rlp_total)
    return "0x" + h[12:].hex()


def verify_merkle_proof(
    leaf: bytes | str, proof: list[bytes | str], root: bytes | str
) -> bool:
    """Verify standard sorted-pair Merkle tree membership proof."""
    def to_b(x: bytes | str) -> bytes:
        if isinstance(x, str):
            clean = x.lower().replace("0x", "")
            return bytes.fromhex(clean.rjust(64, "0"))
        return x

    current = to_b(leaf)
    target_root = to_b(root)

    for p in proof:
        sibling = to_b(p)
        if current < sibling:
            current = _keccak256(current + sibling)
        else:
            current = _keccak256(sibling + current)

    return current == target_root



def compute_merkle_root(leaves: list[bytes | str], sort_pairs: bool = True) -> str:
    """Compute Ethereum Keccak-256 Merkle root from a list of leaf hashes."""
    def _to_b(x: bytes | str) -> bytes:
        if isinstance(x, str):
            clean = x.lower().replace("0x", "")
            if len(clean) == 64 and all(c in "0123456789abcdef" for c in clean):
                return bytes.fromhex(clean)
            return _keccak256(x.encode("utf-8"))
        return x if len(x) == 32 else _keccak256(x)

    if not leaves:
        return "0x" + ("00" * 32)
    layer = [_to_b(leaf) for leaf in leaves]
    while len(layer) > 1:
        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                left, right = layer[i], layer[i + 1]
                if sort_pairs and left > right:
                    left, right = right, left
                next_layer.append(_keccak256(left + right))
            else:
                next_layer.append(layer[i])
        layer = next_layer
    return "0x" + layer[0].hex()


def resolve_4byte_selector(target_selector: str, candidates: list[str]) -> str | None:
    """Find the Solidity function signature whose 4-byte Keccak-256 selector matches `target_selector`."""
    target = target_selector.lower().replace("0x", "")[:8]
    for sig in candidates:
        h = _keccak256(sig.strip().encode("utf-8")).hex()[:8]
        if h == target:
            return sig.strip()
    return None


def crack_keccak256_wordlist(target_hash: str, candidates: list[str], salt: bytes = b"") -> str | None:
    """Find pre-image in candidate list whose Keccak-256 hash (optionally salted) matches `target_hash`."""
    target = target_hash.lower().replace("0x", "")
    for word in candidates:
        w_bytes = word.encode("utf-8")
        if _keccak256(w_bytes + salt).hex() == target:
            return word
        if salt and _keccak256(salt + w_bytes).hex() == target:
            return word
    return None
