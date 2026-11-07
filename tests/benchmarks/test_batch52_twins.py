from __future__ import annotations

import io
import re
import zipfile

from ctf_toolkit.osint_misc.osint_helpers import (
    detect_os_from_user_agent,
    extract_received_sender_ip,
    extract_san_subdomains,
    lookup_city_by_coordinates,
)


def test_twin_736_geotag_jakarta():
    lat, lon = -6.2088, 106.8456
    city = lookup_city_by_coordinates(lat, lon)
    assert city == "jakarta"
    flag = f"FLAG{{twin_{city}}}"
    assert flag == "FLAG{twin_jakarta}"


def test_twin_737_geotag_yogyakarta():
    lat, lon = -7.7956, 110.3695
    city = lookup_city_by_coordinates(lat, lon)
    assert city == "yogyakarta"
    flag = f"FLAG{{twin_{city}}}"
    assert flag == "FLAG{twin_yogyakarta}"


def test_twin_738_geotag_bandung():
    lat, lon = -6.9175, 107.6191
    city = lookup_city_by_coordinates(lat, lon)
    assert city == "bandung"
    flag = f"FLAG{{twin_{city}}}"
    assert flag == "FLAG{twin_bandung}"


def test_twin_739_geotag_surabaya():
    lat, lon = -7.2575, 112.7521
    city = lookup_city_by_coordinates(lat, lon)
    assert city == "surabaya"
    flag = f"FLAG{{twin_{city}}}"
    assert flag == "FLAG{twin_surabaya}"


def test_twin_755_whois_org_mora():
    whois_record = """
    aut-num:        AS131445
    as-name:        MORA-AS-ID
    descr:          PT Mora Telekomunikasi Indonesia
    country:        ID
    org-name:       PT Mora Telekomunikasi Indonesia
    """
    m = re.search(r"org-name:\s*(.*)", whois_record)
    assert m is not None
    org_slug = m.group(1).lower().replace(" ", "_")[:20]
    flag = f"FLAG{{twin_org_{org_slug}}}"
    assert "mora" in flag


def test_twin_756_whois_org_acme():
    whois_record = """
    aut-num:        AS131446
    as-name:        ACME-AS-ID
    org-name:       Acme Corp ID
    country:        ID
    """
    m = re.search(r"org-name:\s*(.*)", whois_record)
    assert m is not None
    org_slug = m.group(1).lower().replace(" ", "_")
    flag = f"FLAG{{twin_org_{org_slug}}}"
    assert flag == "FLAG{twin_org_acme_corp_id}"


def test_twin_757_whois_org_nusantara():
    whois_record = """
    aut-num:        AS131447
    as-name:        NUSANTARA-AS-ID
    org-name:       Nusantara Hosting
    country:        ID
    """
    m = re.search(r"org-name:\s*(.*)", whois_record)
    assert m is not None
    org_slug = m.group(1).lower().replace(" ", "_")
    flag = f"FLAG{{twin_org_{org_slug}}}"
    assert flag == "FLAG{twin_org_nusantara_hosting}"


def test_twin_758_whois_org_cyber():
    whois_record = """
    aut-num:        AS131448
    as-name:        CYBER-AS-ID
    org-name:       Cyber Jaya Ltd
    country:        ID
    """
    m = re.search(r"org-name:\s*(.*)", whois_record)
    assert m is not None
    org_slug = m.group(1).lower().replace(" ", "_")
    flag = f"FLAG{{twin_org_{org_slug}}}"
    assert flag == "FLAG{twin_org_cyber_jaya_ltd}"


def test_twin_759_mail_received_ip1():
    eml = """Received: from mail.example.com (mail.example.com [203.0.1.7])
    by mx.google.com with ESMTPS id abc123
    for <user@example.com>; Fri, 7 Nov 2026 12:00:00 +0700"""
    ip = extract_received_sender_ip(eml)
    assert ip == "203.0.1.7"
    flag = f"FLAG{{twin_sender_ip_{ip}}}"
    assert flag == "FLAG{twin_sender_ip_203.0.1.7}"


def test_twin_760_mail_received_ip2():
    eml = """Received: from outbound.gateway.net (gateway.net [203.0.2.14])
    by mx.target.org; Fri, 7 Nov 2026 12:00:00 +0700"""
    ip = extract_received_sender_ip(eml)
    assert ip == "203.0.2.14"
    flag = f"FLAG{{twin_sender_ip_{ip}}}"
    assert flag == "FLAG{twin_sender_ip_203.0.2.14}"


def test_twin_761_mail_received_ip3():
    eml = """Received: from smtp.relay.org (relay.org [203.0.3.21])
    by mx.dest.net; Fri, 7 Nov 2026 12:00:00 +0700"""
    ip = extract_received_sender_ip(eml)
    assert ip == "203.0.3.21"
    flag = f"FLAG{{twin_sender_ip_{ip}}}"
    assert flag == "FLAG{twin_sender_ip_203.0.3.21}"


def test_twin_762_docx_creator_author1():
    core_xml = b'<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>author_01_lead</dc:creator></cp:coreProperties>'
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
    bio.seek(0)
    with zipfile.ZipFile(bio, "r") as zf:
        xml_content = zf.read("docProps/core.xml").decode("utf-8")
        m = re.search(r"<dc:creator>(.*?)</dc:creator>", xml_content)
        assert m is not None
        author = m.group(1)
    flag = f"FLAG{{twin_docx_author_{author}}}"
    assert flag == "FLAG{twin_docx_author_author_01_lead}"


def test_twin_763_docx_creator_author2():
    core_xml = b'<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>author_02_lead</dc:creator></cp:coreProperties>'
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
    bio.seek(0)
    with zipfile.ZipFile(bio, "r") as zf:
        xml_content = zf.read("docProps/core.xml").decode("utf-8")
        author = re.search(r"<dc:creator>(.*?)</dc:creator>", xml_content).group(1)
    flag = f"FLAG{{twin_docx_author_{author}}}"
    assert flag == "FLAG{twin_docx_author_author_02_lead}"


def test_twin_764_docx_creator_author3():
    core_xml = b'<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>author_03_lead</dc:creator></cp:coreProperties>'
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("docProps/core.xml", core_xml)
    bio.seek(0)
    with zipfile.ZipFile(bio, "r") as zf:
        xml_content = zf.read("docProps/core.xml").decode("utf-8")
        author = re.search(r"<dc:creator>(.*?)</dc:creator>", xml_content).group(1)
    flag = f"FLAG{{twin_docx_author_{author}}}"
    assert flag == "FLAG{twin_docx_author_author_03_lead}"


def test_twin_768_tls_san_corp1():
    cert_txt = """
    X509v3 Subject Alternative Name:
        DNS:vpn1.internal-corp1.id, DNS:portal.internal-corp1.id
    """
    sans = extract_san_subdomains(cert_txt)
    assert "vpn1.internal-corp1.id" in sans
    flag = f"FLAG{{twin_san_{sans[0]}}}"
    assert flag == "FLAG{twin_san_vpn1.internal-corp1.id}"


def test_twin_769_tls_san_corp2():
    cert_txt = """
    X509v3 Subject Alternative Name:
        DNS:vpn2.internal-corp2.id, DNS:portal.internal-corp2.id
    """
    sans = extract_san_subdomains(cert_txt)
    assert "vpn2.internal-corp2.id" in sans
    flag = f"FLAG{{twin_san_{sans[0]}}}"
    assert flag == "FLAG{twin_san_vpn2.internal-corp2.id}"


def test_twin_770_tls_san_corp3():
    cert_txt = """
    X509v3 Subject Alternative Name:
        DNS:vpn3.internal-corp3.id, DNS:portal.internal-corp3.id
    """
    sans = extract_san_subdomains(cert_txt)
    assert "vpn3.internal-corp3.id" in sans
    flag = f"FLAG{{twin_san_{sans[0]}}}"
    assert flag == "FLAG{twin_san_vpn3.internal-corp3.id}"


def test_twin_777_ua_os_windows():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0 Safari/537.36"
    os_name = detect_os_from_user_agent(ua)
    assert os_name == "windows_10"
    flag = f"FLAG{{twin_ua_os_{os_name}}}"
    assert flag == "FLAG{twin_ua_os_windows_10}"


def test_twin_778_ua_os_macos():
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/605.1.15 Safari/605.1.15"
    os_name = detect_os_from_user_agent(ua)
    assert os_name == "macos_13"
    flag = f"FLAG{{twin_ua_os_{os_name}}}"
    assert flag == "FLAG{twin_ua_os_macos_13}"


def test_twin_779_ua_os_android():
    ua = "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 Chrome/112.0 Mobile Safari/537.36"
    os_name = detect_os_from_user_agent(ua)
    assert os_name == "android_13"
    flag = f"FLAG{{twin_ua_os_{os_name}}}"
    assert flag == "FLAG{twin_ua_os_android_13}"


def test_twin_783_wayback_comment1():
    html = "<html><body><!-- secret_token: wayback_comment_01 --><h1>Welcome</h1></body></html>"
    m = re.search(r"<!--\s*secret_token:\s*([a-zA-Z0-9_]+)\s*-->", html)
    assert m is not None
    flag = f"FLAG{{twin_{m.group(1)}}}"
    assert flag == "FLAG{twin_wayback_comment_01}"


def test_twin_784_wayback_comment2():
    html = "<html><body><!-- secret_token: wayback_comment_02 --><h1>Archive</h1></body></html>"
    m = re.search(r"<!--\s*secret_token:\s*([a-zA-Z0-9_]+)\s*-->", html)
    assert m is not None
    flag = f"FLAG{{twin_{m.group(1)}}}"
    assert flag == "FLAG{twin_wayback_comment_02}"


def test_twin_785_wayback_comment3():
    html = "<html><body><!-- secret_token: wayback_comment_03 --><h1>Backup</h1></body></html>"
    m = re.search(r"<!--\s*secret_token:\s*([a-zA-Z0-9_]+)\s*-->", html)
    assert m is not None
    flag = f"FLAG{{twin_{m.group(1)}}}"
    assert flag == "FLAG{twin_wayback_comment_03}"


def test_twin_789_geotag_singapore():
    lat, lon = 1.2897, 103.8501
    city = lookup_city_by_coordinates(lat, lon)
    assert city == "singapore"
    flag = f"FLAG{{twin_{city}}}"
    assert flag == "FLAG{twin_singapore}"


def test_twin_790_geotag_tokyo():
    lat, lon = 35.6762, 139.6503
    city = lookup_city_by_coordinates(lat, lon)
    assert city == "tokyo"
    flag = f"FLAG{{twin_{city}}}"
    assert flag == "FLAG{twin_tokyo}"
