import base64
import io
import re
import struct
import tarfile
from PIL import Image
import numpy as np

from ctf_toolkit.forensics.image_channels import (
    extract_channel_lsb,
)
from ctf_toolkit.forensics.jpeg_tools import (
    concatenate_jpeg_comments,
    extract_all_jpeg_comments_bytes,
)
from ctf_toolkit.forensics.log_hunter import (
    assemble_suricata_alert_fragments,
    extract_b64_url_parameters,
    extract_dns_subdomain_exfiltration,
    extract_mime_encoded_words,
    extract_usb_serial_hex,
)


def test_twin_703_jpeg_split_comments():
    p1 = b"FLAG{twin_jpeg_"
    p2 = b"split_comments}"
    c1 = struct.pack(">2sH", b"\xff\xfe", len(p1) + 2) + p1
    c2 = struct.pack(">2sH", b"\xff\xfe", len(p2) + 2) + p2
    synthetic_jpeg = b"\xff\xd8" + c1 + c2 + b"\xff\xd9"

    all_comments = extract_all_jpeg_comments_bytes(synthetic_jpeg)
    assert len(all_comments) == 2
    assembled = concatenate_jpeg_comments(synthetic_jpeg)
    assert assembled == p1 + p2


def test_twin_704_bitplane_red_1():
    flag = b"FLAG{twin_bp_red_1}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_r = arr[..., 0].flatten()
    flat_r[: len(bits)] = bits << 1
    arr[..., 0] = flat_r.reshape(arr[..., 0].shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_channel_lsb(buf.getvalue(), channel="R", bit_pos=1)
    assert extracted.startswith(flag)


def test_twin_705_bitplane_green_2():
    flag = b"FLAG{twin_bp_green_2}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_g = arr[..., 1].flatten()
    flat_g[: len(bits)] = bits << 2
    arr[..., 1] = flat_g.reshape(arr[..., 1].shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_channel_lsb(buf.getvalue(), channel="G", bit_pos=2)
    assert extracted.startswith(flag)


def test_twin_706_bitplane_blue_3():
    flag = b"FLAG{twin_bp_blue_3}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_b = arr[..., 2].flatten()
    flat_b[: len(bits)] = bits << 3
    arr[..., 2] = flat_b.reshape(arr[..., 2].shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_channel_lsb(buf.getvalue(), channel="B", bit_pos=3)
    assert extracted.startswith(flag)


def test_twin_707_bitplane_red_7_msb():
    flag = b"FLAG{twin_bp_red_msb}"
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_r = arr[..., 0].flatten()
    flat_r[: len(bits)] = bits << 7
    arr[..., 0] = flat_r.reshape(arr[..., 0].shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_channel_lsb(buf.getvalue(), channel="R", bit_pos=7)
    assert extracted.startswith(flag)


def test_twin_708_bitplane_green_4_base64():
    flag = b"FLAG{twin_bp_green_b64}"
    b64_payload = base64.b64encode(flag)
    bits = np.unpackbits(np.frombuffer(b64_payload, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_g = arr[..., 1].flatten()
    flat_g[: len(bits)] = bits << 4
    arr[..., 1] = flat_g.reshape(arr[..., 1].shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_channel_lsb(buf.getvalue(), channel="G", bit_pos=4)
    assert extracted.startswith(b64_payload)
    assert base64.b64decode(extracted[: len(b64_payload)]) == flag


def test_twin_709_bitplane_blue_5_reversed():
    flag = b"FLAG{twin_bp_blue_rev}"
    rev_flag = flag[::-1]
    bits = np.unpackbits(np.frombuffer(rev_flag, dtype=np.uint8))
    arr = np.zeros((10, len(bits) // 10 + 1, 3), dtype=np.uint8)
    flat_b = arr[..., 2].flatten()
    flat_b[: len(bits)] = bits << 5
    arr[..., 2] = flat_b.reshape(arr[..., 2].shape)
    im = Image.fromarray(arr)
    buf = io.BytesIO()
    im.save(buf, format="PNG")

    extracted = extract_channel_lsb(buf.getvalue(), channel="B", bit_pos=5)
    assert extracted.startswith(rev_flag)
    assert extracted[: len(flag)][::-1] == flag


def test_twin_710_systemd_backdoor_unit():
    unit_text = b"[Unit]\nDescription=Shadow Helper\n[Service]\nExecStart=/usr/bin/python3 -c 'import os; FLAG{twin_systemd_unit}'\n"
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("etc/systemd/system/helper.service")
        ti.size = len(unit_text)
        tf.addfile(ti, io.BytesIO(unit_text))

    with tarfile.open(fileobj=io.BytesIO(tar_buf.getvalue()), mode="r:gz") as tf:
        content = tf.extractfile("etc/systemd/system/helper.service").read()
    m = re.search(rb"FLAG\{[^}]+\}", content)
    assert m is not None
    assert m.group() == b"FLAG{twin_systemd_unit}"


def test_twin_711_suid_dropper_binary():
    payload = b"#!/bin/bash\n# FLAG{twin_suid_dropper}\n"
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("usr/local/bin/helper")
        ti.size = len(payload)
        ti.mode = 0o4755
        tf.addfile(ti, io.BytesIO(payload))

    with tarfile.open(fileobj=io.BytesIO(tar_buf.getvalue()), mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.mode & 0o4000:
                suid_content = tf.extractfile(member).read()
                m = re.search(rb"FLAG\{[^}]+\}", suid_content)
                assert m.group() == b"FLAG{twin_suid_dropper}"


def test_twin_712_disk_slack_recovery():
    slack_data = b"\x00" * 512 + b"SECRET_NOTE: FLAG{twin_slack_carved}" + b"\x00" * 256
    m = re.search(rb"FLAG\{[^}]+\}", slack_data)
    assert m.group() == b"FLAG{twin_slack_carved}"


def test_twin_713_authlog_bruteforce_correlation():
    log_text = """Oct 29 04:01:01 srv sshd[101]: Failed password for invalid user admin from 10.0.0.1
Oct 29 04:01:02 srv sshd[102]: Failed password for invalid user admin from 10.0.0.1
Oct 29 04:01:05 srv sshd[103]: Accepted password for root from 10.0.0.1 port 52210 ssh2: FLAG{twin_authlog_win}"""
    m = re.search(r"FLAG\{[^}]+\}", log_text)
    assert m.group() == "FLAG{twin_authlog_win}"


def test_twin_714_shell_script_base64_payload():
    flag = b"FLAG{twin_installer_b64}"
    b64_stage = base64.b64encode(b"echo " + flag).decode()
    script = f"#!/bin/sh\necho '{b64_stage}' | base64 -d | sh\n"

    extracted_b64 = re.search(r"echo '([^']+)' \| base64 -d", script).group(1)
    decoded_stage = base64.b64decode(extracted_b64)
    m = re.search(rb"FLAG\{[^}]+\}", decoded_stage)
    assert m.group() == flag


def test_twin_715_heap_dump_string_table():
    heap_slice = b"\x90\x00\x00\x00\x04\x00\x00\x00" + b"FLAG{twin_heap_string_table}" + b"\x00\x00\x00\x00"
    m = re.search(rb"FLAG\{[^}]+\}", heap_slice)
    assert m.group() == b"FLAG{twin_heap_string_table}"


def test_twin_716_process_environ_inspection():
    environ_bin = b"PATH=/bin:/usr/bin\x00USER=root\x00SECRET_KEY=FLAG{twin_environ_vars}\x00HOME=/root\x00"
    env_dict = dict(item.split(b"=", 1) for item in environ_bin.split(b"\x00") if b"=" in item)
    assert env_dict.get(b"SECRET_KEY") == b"FLAG{twin_environ_vars}"


def test_twin_717_session_slab_allocator():
    flag = b"FLAG{twin_session_slab}"
    slab_obj = struct.pack("<Q16s", 1698500000, b"sess_1234567890a") + flag.ljust(32, b"\x00")
    recovered_flag = slab_obj[24:56].rstrip(b"\x00")
    assert recovered_flag == flag


def test_twin_718_heap_cookie_base64():
    flag = b"FLAG{twin_heap_b64_cookie}"
    encoded_cookie = base64.b64encode(b"session=" + flag).decode()
    heap_chunk = f"HTTP/1.1 200 OK\r\nSet-Cookie: auth={encoded_cookie}; path=/\r\n\r\n".encode()

    m = re.search(rb"auth=([A-Za-z0-9+/=]+)", heap_chunk)
    dec = base64.b64decode(m.group(1))
    assert flag in dec


def test_twin_719_dns_subdomain_exfiltration():
    flag = b"FLAG{twin_dns_exfil}"
    hex_data = flag.hex()
    chunks = [hex_data[i : i + 8] for i in range(0, len(hex_data), 8)]
    log_lines = []
    for idx, chunk in enumerate(chunks):
        log_lines.append(f"Nov 6 10:00:{idx:02d} dnsmasq[123]: query[A] q{idx:02d}-{chunk}.tunnel.exfil.org from 10.0.0.5")
    log_text = "\n".join(log_lines)

    recovered = extract_dns_subdomain_exfiltration(log_text, "tunnel.exfil.org")
    assert recovered == flag


def test_twin_720_log_correlation_ssh_web():
    auth_log = "Nov 6 03:14:00 srv sshd[999]: Accepted publickey for backup from 192.168.1.50\n"
    access_log = '192.168.1.50 - - [06/Nov/2026:03:14:05 +0000] "GET /download?token=FLAG{twin_log_correlation} HTTP/1.1" 200 1234\n'

    m_ip = re.search(r"from ([\d\.]+)", auth_log).group(1)
    assert m_ip == "192.168.1.50"
    m_flag = re.search(rf"{re.escape(m_ip)}.*?token=([^ ]+)", access_log)
    assert m_flag.group(1) == "FLAG{twin_log_correlation}"


def test_twin_721_web_pixel_tracker_base64():
    flag = b"FLAG{twin_pixel_tracker}"
    b64_val = base64.b64encode(flag).decode()
    log_line = f'10.10.10.1 - - [06/Nov/2026:04:00:00 +0000] "GET /pixel.png?data={b64_val} HTTP/1.1" 200 43\n'

    params = extract_b64_url_parameters(log_line)
    assert flag in params


def test_twin_722_suricata_alert_fragmentation():
    flag = b"FLAG{twin_suricata_covert}"
    b64_str = base64.b64encode(flag).decode()
    step = len(b64_str) // 3 + 1
    frags = [b64_str[i : i + step] for i in range(0, len(b64_str), step)]
    log_lines = []
    for i, frag in enumerate(frags):
        log_lines.append(f"Nov 6 05:00:00 [**] [1:900:1] ET EXFIL Covert Channel frag={i}/{len(frags)} data={frag} [**] {{TCP}}")
    log_text = "\n".join(log_lines)

    recovered = assemble_suricata_alert_fragments(log_text)
    assert recovered == flag


def test_twin_723_waf_audit_body_inspection():
    flag = b"FLAG{twin_waf_audit_body}"
    waf_log = f'--boundary\nContent-Disposition: form-data; name="payload"\n\n{base64.b64encode(flag).decode()}\n--boundary--'
    m = re.search(r"name=\"payload\"\s*\n\s*([A-Za-z0-9+/=]+)", waf_log)
    dec = base64.b64decode(m.group(1))
    assert dec == flag


def test_twin_724_winevent_remote_logon():
    event_log = """Event[4624]: An account was successfully logged on.
Subject: Security ID: S-1-5-18
New Logon:
  Security ID: S-1-5-21-3901-1001
  Account Name: Administrator
  Logon ID: 0x3E7
  Flag: FLAG{twin_winevent_logon}"""
    m = re.search(r"FLAG\{[^}]+\}", event_log)
    assert m.group() == "FLAG{twin_winevent_logon}"


def test_twin_725_mail_mime_encoded_subject():
    flag = "FLAG{twin_mail_mime_subject}"
    mime_encoded = "=?UTF-8?B?" + base64.b64encode(flag.encode()).decode() + "?="
    log_line = f"Nov 6 06:00:00 mail postfix/cleanup[50]: message-id=<123@relay>: Subject: {mime_encoded}\n"

    decoded_subjects = extract_mime_encoded_words(log_line)
    assert flag in decoded_subjects


def test_twin_726_kernel_usb_serial_hex():
    flag = b"FLAG{twin_usb_serial_hex}"
    hex_serial = flag.hex().upper()
    log_line = f"Nov 6 11:00:00 kiosk-pc kernel: usb 1-2: SerialNumber: {hex_serial}\n"

    serials = extract_usb_serial_hex(log_line)
    assert flag in serials


def test_twin_727_redis_monitor_injection():
    flag = b"FLAG{twin_redis_monitor}"
    b64_val = base64.b64encode(flag).decode()
    redis_line = f'1698500000.123456 [0 10.0.0.1:45678] "SET" "cache:session:123" "{b64_val}"\n'

    m = re.search(r'"SET"\s+"[^"]+"\s+"([A-Za-z0-9+/=]+)"', redis_line)
    dec = base64.b64decode(m.group(1))
    assert dec == flag
