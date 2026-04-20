from __future__ import annotations

import hashlib


def digest(data: bytes, algorithm: str) -> str:
    algo = algorithm.lower()
    if algo not in {"md5", "sha1", "sha256"}:
        raise ValueError("algoritma hash belum didukung")
    return hashlib.new(algo, data).hexdigest()


LENGTH_EXTENSION_NOTE = (
    "Length-extension attack helper belum diimplementasikan; gunakan library khusus jika dibutuhkan."
)
