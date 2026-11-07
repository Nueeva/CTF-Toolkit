from __future__ import annotations

import io
import json
import re
import zipfile

from ctf_toolkit.osint_misc.osint_helpers import (
    classify_login_ip,
    extract_git_secret_from_config,
    extract_san_subdomains,
    lookup_city_by_coordinates,
    parse_ctlog_entries,
)


def test_twin_791_geotag_paris():
    lat, lon = 48.8566, 2.3522
    city = lookup_city_by_coordinates(lat, lon)
    assert city == "paris"
    flag = f"FLAG{{twin_{city}}}"
    assert flag == "FLAG{twin_paris}"


def test_twin_792_social_meta1():
    raw_json = '{"post_id": 1, "caption": "vacation", "meta": {"hidden_tag": "FLAG{twin_social_meta_01}"}}'
    data = json.loads(raw_json)
    flag = data["meta"]["hidden_tag"]
    assert flag == "FLAG{twin_social_meta_01}"


def test_twin_793_social_meta2():
    raw_json = '{"post_id": 2, "caption": "sunset", "meta": {"hidden_tag": "FLAG{twin_social_meta_02}"}}'
    data = json.loads(raw_json)
    flag = data["meta"]["hidden_tag"]
    assert flag == "FLAG{twin_social_meta_02}"


def test_twin_794_social_meta3():
    raw_json = '{"post_id": 3, "caption": "coffee", "meta": {"hidden_tag": "FLAG{twin_social_meta_03}"}}'
    data = json.loads(raw_json)
    flag = data["meta"]["hidden_tag"]
    assert flag == "FLAG{twin_social_meta_03}"


def test_twin_795_ctlog_staging1():
    ctlog = "crt.sh results:\nid=1001 | stage1.secret-corp1.id\nid=1002 | www.corp1.id\n"
    entries = parse_ctlog_entries(ctlog)
    assert "stage1.secret-corp1.id" in entries
    staging = [e for e in entries if e.startswith("stage")][0]
    flag = f"FLAG{{twin_ctlog_{staging}}}"
    assert flag == "FLAG{twin_ctlog_stage1.secret-corp1.id}"


def test_twin_796_ctlog_staging2():
    ctlog = "crt.sh results:\nid=2001 | stage2.secret-corp2.id\nid=2002 | www.corp2.id\n"
    entries = parse_ctlog_entries(ctlog)
    assert "stage2.secret-corp2.id" in entries
    staging = [e for e in entries if e.startswith("stage")][0]
    flag = f"FLAG{{twin_ctlog_{staging}}}"
    assert flag == "FLAG{twin_ctlog_stage2.secret-corp2.id}"


def test_twin_797_landmark_monas():
    clue = "Clue: foto ikonik, teks di plakat berbunyi 'Monas'."
    landmark = re.search(r"'(Monas)'", clue).group(1).lower()
    flag = f"FLAG{{twin_landmark_{landmark}}}"
    assert flag == "FLAG{twin_landmark_monas}"


def test_twin_798_landmark_borobudur():
    clue = "Clue: foto ikonik, teks di plakat berbunyi 'Borobudur'."
    landmark = re.search(r"'(Borobudur)'", clue).group(1).lower()
    flag = f"FLAG{{twin_landmark_{landmark}}}"
    assert flag == "FLAG{twin_landmark_borobudur}"


def test_twin_799_landmark_eiffel():
    clue = "Clue: foto ikonik, teks di plakat berbunyi 'Eiffel Tower'."
    landmark = re.search(r"'(Eiffel Tower)'", clue).group(1).lower().replace(" ", "_")
    flag = f"FLAG{{twin_landmark_{landmark}}}"
    assert flag == "FLAG{twin_landmark_eiffel_tower}"


def test_twin_800_login_tor():
    ip = "185.220.101.5"
    tag = classify_login_ip(ip)
    assert tag == "tor_exit"
    flag = f"FLAG{{twin_login_{tag}}}"
    assert flag == "FLAG{twin_login_tor_exit}"


def test_twin_801_login_indonesia_isp():
    ip = "103.10.66.1"
    tag = classify_login_ip(ip)
    assert tag == "indonesia_isp"
    flag = f"FLAG{{twin_login_{tag}}}"
    assert flag == "FLAG{twin_login_indonesia_isp}"


def test_twin_802_login_google_dns():
    ip = "8.8.8.8"
    tag = classify_login_ip(ip)
    assert tag == "google_dns"
    flag = f"FLAG{{twin_login_{tag}}}"
    assert flag == "FLAG{twin_login_google_dns}"


def test_twin_1513_docx_creator1():
    core_xml = b'<?xml version="1.0"?><cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>FLAG{twin_docx_creator_01}</dc:creator></cp:coreProperties>'
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
    bio.seek(0)
    with zipfile.ZipFile(bio, "r") as zf:
        xml_str = zf.read("docProps/core.xml").decode("utf-8")
        creator = re.search(r"<dc:creator>(.*?)</dc:creator>", xml_str).group(1)
    assert creator == "FLAG{twin_docx_creator_01}"


def test_twin_1514_docx_creator2():
    core_xml = b'<?xml version="1.0"?><cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>FLAG{twin_docx_creator_02}</dc:creator></cp:coreProperties>'
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
    bio.seek(0)
    with zipfile.ZipFile(bio, "r") as zf:
        xml_str = zf.read("docProps/core.xml").decode("utf-8")
        creator = re.search(r"<dc:creator>(.*?)</dc:creator>", xml_str).group(1)
    assert creator == "FLAG{twin_docx_creator_02}"


def test_twin_1515_docx_creator3():
    core_xml = b'<?xml version="1.0"?><cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>FLAG{twin_docx_creator_03}</dc:creator></cp:coreProperties>'
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
    bio.seek(0)
    with zipfile.ZipFile(bio, "r") as zf:
        xml_str = zf.read("docProps/core.xml").decode("utf-8")
        creator = re.search(r"<dc:creator>(.*?)</dc:creator>", xml_str).group(1)
    assert creator == "FLAG{twin_docx_creator_03}"


def test_twin_1516_docx_creator4():
    core_xml = b'<?xml version="1.0"?><cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>FLAG{twin_docx_creator_04}</dc:creator></cp:coreProperties>'
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
    bio.seek(0)
    with zipfile.ZipFile(bio, "r") as zf:
        xml_str = zf.read("docProps/core.xml").decode("utf-8")
        creator = re.search(r"<dc:creator>(.*?)</dc:creator>", xml_str).group(1)
    assert creator == "FLAG{twin_docx_creator_04}"


def test_twin_1517_docx_creator5():
    core_xml = b'<?xml version="1.0"?><cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>FLAG{twin_docx_creator_05}</dc:creator></cp:coreProperties>'
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
    bio.seek(0)
    with zipfile.ZipFile(bio, "r") as zf:
        xml_str = zf.read("docProps/core.xml").decode("utf-8")
        creator = re.search(r"<dc:creator>(.*?)</dc:creator>", xml_str).group(1)
    assert creator == "FLAG{twin_docx_creator_05}"


def test_twin_1531_git_secret1():
    config = """[remote "origin"]\n\turl = https://user:FLAG{twin_git_secret_01}@git.example.com/app.git\n"""
    sec = extract_git_secret_from_config(config)
    assert sec == "FLAG{twin_git_secret_01}"


def test_twin_1532_git_secret2():
    config = """[remote "origin"]\n\turl = https://user:FLAG{twin_git_secret_02}@git.example.com/app.git\n"""
    sec = extract_git_secret_from_config(config)
    assert sec == "FLAG{twin_git_secret_02}"


def test_twin_1533_git_secret3():
    config = """[remote "origin"]\n\turl = https://user:FLAG{twin_git_secret_03}@git.example.com/app.git\n"""
    sec = extract_git_secret_from_config(config)
    assert sec == "FLAG{twin_git_secret_03}"


def test_twin_1534_git_secret4():
    config = """[remote "origin"]\n\turl = https://user:FLAG{twin_git_secret_04}@git.example.com/app.git\n"""
    sec = extract_git_secret_from_config(config)
    assert sec == "FLAG{twin_git_secret_04}"


def test_twin_1535_git_secret5():
    config = """[remote "origin"]\n\turl = https://user:FLAG{twin_git_secret_05}@git.example.com/app.git\n"""
    sec = extract_git_secret_from_config(config)
    assert sec == "FLAG{twin_git_secret_05}"


def test_twin_1536_cert_san_flag1():
    cert_txt = "X509v3 Subject Alternative Name:\n    DNS:www.example.com, DNS:FLAG{twin_cert_san_01}.internal.example.com"
    sans = extract_san_subdomains(cert_txt)
    m = [re.search(r"(FLAG\{[^}]+\})", s) for s in sans if re.search(r"(FLAG\{[^}]+\})", s)]
    assert m
    flag = m[0].group(1)
    assert flag == "FLAG{twin_cert_san_01}"


def test_twin_1537_cert_san_flag2():
    cert_txt = "X509v3 Subject Alternative Name:\n    DNS:www.example.com, DNS:FLAG{twin_cert_san_02}.internal.example.com"
    sans = extract_san_subdomains(cert_txt)
    m = [re.search(r"(FLAG\{[^}]+\})", s) for s in sans if re.search(r"(FLAG\{[^}]+\})", s)]
    assert m
    flag = m[0].group(1)
    assert flag == "FLAG{twin_cert_san_02}"


def test_twin_1538_cert_san_flag3():
    cert_txt = "X509v3 Subject Alternative Name:\n    DNS:www.example.com, DNS:FLAG{twin_cert_san_03}.internal.example.com"
    sans = extract_san_subdomains(cert_txt)
    m = [re.search(r"(FLAG\{[^}]+\})", s) for s in sans if re.search(r"(FLAG\{[^}]+\})", s)]
    assert m
    flag = m[0].group(1)
    assert flag == "FLAG{twin_cert_san_03}"
