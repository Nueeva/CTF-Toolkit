"""Flag-format coverage added in v4.0.1.

The detection prefix set was widened from {GETSFLAG, CTF, FLAG, CT, LKS}
to the formats verified in the 2026-11-08 flag-format research: global
platforms (HTB/CHTB, THM, picoCTF, CTFlearn), recurring events (dice,
hope, ASIS, SEKAI, OOO, ARKAV) and Indonesian edition families whose
prefix is a brand stem plus an optional edition number (COMPFEST17,
GEMASTIK19, WRECKIT40, HOLOGY8, slashroot8, TECHCOMFEST23, ARA6,
HIDC2026). GETSFLAG and LKS are intentionally kept.

NOTE: run_tests.py only discovers module-level test_* functions.
"""
from ctf_toolkit.osint_misc.profile_miner import mine_profile_handles
from ctf_toolkit.pipeline.recipe import op_flag_scan
from ctf_toolkit.triage.analyzer import triage_data

NEW_FORMATS = [
    "HTB{test_flag}", "CHTB{test_flag}", "THM{test_flag}",
    "CTFlearn{test_flag}", "DICE{test_flag}", "HOPE{test_flag}",
    "ASIS{test_flag}", "SEKAI{test_flag}", "OOO{test_flag}",
    "picoCTF{test_flag}", "ARKAV{test_flag}",
    "COMPFEST17{test_flag}", "COMPFEST{test_flag}",
    "GEMASTIK19{test_flag}", "WRECKIT40{test_flag}",
    "HOLOGY8{test_flag}", "SLASHROOT8{test_flag}",
    "TECHCOMFEST23{test_flag}", "ARA6{test_flag}", "HIDC2026{test_flag}",
]

KEPT_FORMATS = ["GETSFLAG{test_flag}", "LKS{test_flag}", "FLAG{test_flag}",
                "CTF{test_flag}", "CT{test_flag}"]

LOWERCASE_FORMATS = ["dice{test_flag}", "gemastik{test_flag}",
                     "slashroot8{test_flag}", "hology3{test_flag}",
                     "lactf{test_flag}", "actf{test_flag}"]

NEGATIVES = ["RANDOM{test_flag}", "COMPFESTX{test_flag}", "HTB test_flag",
             "SOME{test_flag}"]


def test_flag_scan_new_formats():
    for flag in NEW_FORMATS:
        assert flag in op_flag_scan(f"prefix {flag} suffix"), flag


def test_flag_scan_kept_formats():
    for flag in KEPT_FORMATS:
        assert flag in op_flag_scan(f"x {flag} y"), flag


def test_flag_scan_lowercase_formats():
    for flag in LOWERCASE_FORMATS:
        assert flag in op_flag_scan(f"x {flag} y"), flag


def test_flag_scan_negatives():
    for probe in NEGATIVES:
        assert op_flag_scan(probe) == probe, probe


def test_profile_miner_formats():
    text = " ".join(LOWERCASE_FORMATS + ["COMPFEST16{abc}", "ARA{abc}"])
    flags = mine_profile_handles(text)["flags"]
    for flag in LOWERCASE_FORMATS:
        assert flag in flags, flag
    assert "COMPFEST16{abc}" in flags


def test_profile_miner_negatives():
    assert mine_profile_handles(" ".join(NEGATIVES))["flags"] == []


def test_triage_finds_new_formats():
    for flag in ["HTB{triage_flag}", "COMPFEST17{triage_flag}",
                 "dice{triage_flag}"]:
        rep = triage_data(f"xx {flag} yy".encode())
        assert flag in rep.flags_found, flag
