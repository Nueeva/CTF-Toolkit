from __future__ import annotations

import random
from ctf_toolkit.crypto.substitution_solver import (
    score_quadgrams,
    solve_substitution_quipquip,
)


def test_score_quadgrams() -> None:
    # High frequency English quadgrams must score significantly higher than random noise
    english_phrase = "THIS IS THE BEST CIPHER IN THE WORLD"
    random_noise = "ZXQJ VKBW PZTL MYNR BFCQ XKVZ PLWT"

    score_eng = score_quadgrams(english_phrase)
    score_rnd = score_quadgrams(random_noise)

    assert score_eng > score_rnd
    assert score_eng > -250.0


def test_solve_substitution_short_guard() -> None:
    res = solve_substitution_quipquip("SHORT", max_restarts=2)
    assert res["success"] is False
    assert "too short" in res["error"]


def test_solve_substitution_known_caesar_mapping() -> None:
    # Test substitution solver with Caesar shift and verify high score & successful deciphering
    plain = "THIS IS A SECRET MESSAGE FOR THE CAPTURE THE FLAG COMPETITION AND WE ARE TESTING QUADGRAMS"
    rot3 = "WKLV LV D VHFUHW PHVVDJH IRU WKH FDSWXUH WKH IODJ FRPSHWLWLRQ DQG ZH DUH WHVWLQJ TXDGJUDPV"

    res = solve_substitution_quipquip(rot3, max_restarts=15, iterations_per_restart=1000)
    assert res["success"] is True
    assert res["score"] > -999.0
    assert len(res["decrypted_text"]) == len(rot3)
