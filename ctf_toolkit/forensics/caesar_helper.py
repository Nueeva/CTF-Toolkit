from __future__ import annotations

from ctf_toolkit.crypto.classical import rot_n

CAESAR_HINT_WORDS = ("flag", "ctf", "lks", "lksjaktim", "key")


def suggest_caesar_candidates(text: str, top_n: int = 5) -> list[tuple[int, str]]:
    candidates: list[tuple[int, int, str]] = []
    for shift in range(26):
        plain = rot_n(text, -shift)
        lower = plain.lower()
        word_score = sum(3 for word in CAESAR_HINT_WORDS if word in lower)
        letter_score = sum(1 for ch in plain if ch in " ETAOINetaoin")
        score = word_score + letter_score
        candidates.append((score, shift, plain))

    candidates.sort(key=lambda item: item[0], reverse=True)
    return [(shift, plain) for _, shift, plain in candidates[: max(1, top_n)]]
