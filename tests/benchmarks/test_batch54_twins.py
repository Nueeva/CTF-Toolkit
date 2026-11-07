from __future__ import annotations

import json
import re

from ctf_toolkit.osint_misc.osint_helpers import (
    extract_git_commit_secrets,
    extract_package_event_notes,
    extract_redirect_hop_notes,
    extract_san_subdomains,
    extract_tls_subject_cn,
)


def test_twin_1539_cert_san_flag4():
    cert_txt = "X509v3 Subject Alternative Name:\n    DNS:www.example.com, DNS:FLAG{twin_cert_san_04}.internal.example.com"
    sans = extract_san_subdomains(cert_txt)
    m = [re.search(r"(FLAG\{[^}]+\})", s) for s in sans if re.search(r"(FLAG\{[^}]+\})", s)]
    assert m
    assert m[0].group(1) == "FLAG{twin_cert_san_04}"


def test_twin_1540_cert_san_flag5():
    cert_txt = "X509v3 Subject Alternative Name:\n    DNS:www.example.com, DNS:FLAG{twin_cert_san_05}.internal.example.com"
    sans = extract_san_subdomains(cert_txt)
    m = [re.search(r"(FLAG\{[^}]+\})", s) for s in sans if re.search(r"(FLAG\{[^}]+\})", s)]
    assert m
    assert m[0].group(1) == "FLAG{twin_cert_san_05}"


def test_twin_1546_shortlink_redirect1():
    data = {
        "hops": [
            {"url": "https://sho.rt/a1", "status": 301, "location": "https://sho.rt/b"},
            {"url": "https://sho.rt/b", "status": 200, "note": "FLAG{twin_shortlink_01}"},
        ]
    }
    notes = extract_redirect_hop_notes(data)
    assert notes == ["FLAG{twin_shortlink_01}"]


def test_twin_1547_shortlink_redirect2():
    data = {
        "hops": [
            {"url": "https://sho.rt/a2", "status": 301, "location": "https://sho.rt/b"},
            {"url": "https://sho.rt/b", "status": 200, "note": "FLAG{twin_shortlink_02}"},
        ]
    }
    notes = extract_redirect_hop_notes(data)
    assert notes == ["FLAG{twin_shortlink_02}"]


def test_twin_1548_shortlink_redirect3():
    data = {
        "hops": [
            {"url": "https://sho.rt/a3", "status": 301, "location": "https://sho.rt/b"},
            {"url": "https://sho.rt/b", "status": 200, "note": "FLAG{twin_shortlink_03}"},
        ]
    }
    notes = extract_redirect_hop_notes(data)
    assert notes == ["FLAG{twin_shortlink_03}"]


def test_twin_1549_shortlink_redirect4():
    data = {
        "hops": [
            {"url": "https://sho.rt/a4", "status": 301, "location": "https://sho.rt/b"},
            {"url": "https://sho.rt/b", "status": 200, "note": "FLAG{twin_shortlink_04}"},
        ]
    }
    notes = extract_redirect_hop_notes(data)
    assert notes == ["FLAG{twin_shortlink_04}"]


def test_twin_1550_shortlink_redirect5():
    data = {
        "hops": [
            {"url": "https://sho.rt/a5", "status": 301, "location": "https://sho.rt/b"},
            {"url": "https://sho.rt/b", "status": 200, "note": "FLAG{twin_shortlink_05}"},
        ]
    }
    notes = extract_redirect_hop_notes(data)
    assert notes == ["FLAG{twin_shortlink_05}"]


def test_twin_1566_ct_log_json1():
    entries = [{"name_value": "example.com"}, {"name_value": "FLAG{twin_ct_log_01}.dev.example.com"}]
    flags = [re.search(r"(FLAG\{[^}]+\})", e["name_value"]).group(1) for e in entries if "FLAG{" in e["name_value"]]
    assert flags == ["FLAG{twin_ct_log_01}"]


def test_twin_1567_ct_log_json2():
    entries = [{"name_value": "example.com"}, {"name_value": "FLAG{twin_ct_log_02}.dev.example.com"}]
    flags = [re.search(r"(FLAG\{[^}]+\})", e["name_value"]).group(1) for e in entries if "FLAG{" in e["name_value"]]
    assert flags == ["FLAG{twin_ct_log_02}"]


def test_twin_1568_ct_log_json3():
    entries = [{"name_value": "example.com"}, {"name_value": "FLAG{twin_ct_log_03}.dev.example.com"}]
    flags = [re.search(r"(FLAG\{[^}]+\})", e["name_value"]).group(1) for e in entries if "FLAG{" in e["name_value"]]
    assert flags == ["FLAG{twin_ct_log_03}"]


def test_twin_1569_ct_log_json4():
    entries = [{"name_value": "example.com"}, {"name_value": "FLAG{twin_ct_log_04}.dev.example.com"}]
    flags = [re.search(r"(FLAG\{[^}]+\})", e["name_value"]).group(1) for e in entries if "FLAG{" in e["name_value"]]
    assert flags == ["FLAG{twin_ct_log_04}"]


def test_twin_1575_git_commit_msg1():
    gitlog = "commit 123\nAuthor: dev\n\n    fix: remove secret FLAG{twin_commit_msg_01}\n"
    secrets = extract_git_commit_secrets(gitlog)
    assert secrets == ["FLAG{twin_commit_msg_01}"]


def test_twin_1576_git_commit_msg2():
    gitlog = "commit 124\nAuthor: dev\n\n    fix: remove secret FLAG{twin_commit_msg_02}\n"
    secrets = extract_git_commit_secrets(gitlog)
    assert secrets == ["FLAG{twin_commit_msg_02}"]


def test_twin_1577_git_commit_msg3():
    gitlog = "commit 125\nAuthor: dev\n\n    fix: remove secret FLAG{twin_commit_msg_03}\n"
    secrets = extract_git_commit_secrets(gitlog)
    assert secrets == ["FLAG{twin_commit_msg_03}"]


def test_twin_1578_git_commit_msg4():
    gitlog = "commit 126\nAuthor: dev\n\n    fix: remove secret FLAG{twin_commit_msg_04}\n"
    secrets = extract_git_commit_secrets(gitlog)
    assert secrets == ["FLAG{twin_commit_msg_04}"]


def test_twin_1579_git_commit_msg5():
    gitlog = "commit 127\nAuthor: dev\n\n    fix: remove secret FLAG{twin_commit_msg_05}\n"
    secrets = extract_git_commit_secrets(gitlog)
    assert secrets == ["FLAG{twin_commit_msg_05}"]


def test_twin_1590_tls_cn_subdomain1():
    tls_text = "subject=CN = FLAG{twin_tls_subdomain_01}.svc.example.com\nissuer=CN = R3"
    cn = extract_tls_subject_cn(tls_text)
    m = re.search(r"(FLAG\{[^}]+\})", cn)
    assert m is not None
    assert m.group(1) == "FLAG{twin_tls_subdomain_01}"


def test_twin_1591_tls_cn_subdomain2():
    tls_text = "subject=CN = FLAG{twin_tls_subdomain_02}.svc.example.com\nissuer=CN = R3"
    cn = extract_tls_subject_cn(tls_text)
    m = re.search(r"(FLAG\{[^}]+\})", cn)
    assert m is not None
    assert m.group(1) == "FLAG{twin_tls_subdomain_02}"


def test_twin_1592_tls_cn_subdomain3():
    tls_text = "subject=CN = FLAG{twin_tls_subdomain_03}.svc.example.com\nissuer=CN = R3"
    cn = extract_tls_subject_cn(tls_text)
    m = re.search(r"(FLAG\{[^}]+\})", cn)
    assert m is not None
    assert m.group(1) == "FLAG{twin_tls_subdomain_03}"


def test_twin_1593_tls_cn_subdomain4():
    tls_text = "subject=CN = FLAG{twin_tls_subdomain_04}.svc.example.com\nissuer=CN = R3"
    cn = extract_tls_subject_cn(tls_text)
    m = re.search(r"(FLAG\{[^}]+\})", cn)
    assert m is not None
    assert m.group(1) == "FLAG{twin_tls_subdomain_04}"


def test_twin_1599_package_tracking1():
    data = {
        "tracking": "JNE1001",
        "events": [
            {"t": "picked up"},
            {"t": "delivered", "signature_note": "FLAG{twin_paket_kirim_01}"},
        ],
    }
    notes = extract_package_event_notes(data)
    assert notes == ["FLAG{twin_paket_kirim_01}"]


def test_twin_1600_package_tracking2():
    data = {
        "tracking": "JNE1002",
        "events": [
            {"t": "picked up"},
            {"t": "delivered", "signature_note": "FLAG{twin_paket_kirim_02}"},
        ],
    }
    notes = extract_package_event_notes(data)
    assert notes == ["FLAG{twin_paket_kirim_02}"]


def test_twin_1601_package_tracking3():
    data = {
        "tracking": "JNE1003",
        "events": [
            {"t": "picked up"},
            {"t": "delivered", "signature_note": "FLAG{twin_paket_kirim_03}"},
        ],
    }
    notes = extract_package_event_notes(data)
    assert notes == ["FLAG{twin_paket_kirim_03}"]


def test_twin_1602_package_tracking4():
    data = {
        "tracking": "JNE1004",
        "events": [
            {"t": "picked up"},
            {"t": "delivered", "signature_note": "FLAG{twin_paket_kirim_04}"},
        ],
    }
    notes = extract_package_event_notes(data)
    assert notes == ["FLAG{twin_paket_kirim_04}"]


def test_twin_1603_package_tracking5():
    data = {
        "tracking": "JNE1005",
        "events": [
            {"t": "picked up"},
            {"t": "delivered", "signature_note": "FLAG{twin_paket_kirim_05}"},
        ],
    }
    notes = extract_package_event_notes(data)
    assert notes == ["FLAG{twin_paket_kirim_05}"]
