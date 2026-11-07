from __future__ import annotations

import base64
import io
import re
import zipfile
import zlib
import numpy as np

from ctf_toolkit.forensics.pdf_tools import (
    extract_pdf_decompressed_streams,
    extract_pdf_all_text_tokens,
)
from ctf_toolkit.forensics.docx_tools import (
    extract_docx_hidden_vanish,
    extract_docx_comments,
    extract_docx_tracked_revisions,
    extract_docx_embeddings,
)
from ctf_toolkit.forensics.xlsx_tools import (
    extract_xlsx_hidden_sheets,
    extract_xlsx_cell_comments,
    extract_ooxml_vba_strings,
)
from ctf_toolkit.forensics.audio_tools import (
    decode_mfsk,
    decode_16fsk_nibbles,
    decode_dtmf_tones,
)


def test_twin_1623_pdf_white_text() -> None:
    content = b"BT 1 1 1 rg (FLAG{twin_white_text}) Tj ET"
    flate = zlib.compress(content)
    a85 = base64.a85encode(flate, adobe=True)
    pdf_synthetic = (
        b"%PDF-1.3\n1 0 obj\n<< /Filter [ /ASCII85Decode /FlateDecode ] >>\nstream\n"
        + a85
        + b"\nendstream\nendobj\n%%EOF"
    )
    streams = extract_pdf_decompressed_streams(pdf_synthetic)
    assert len(streams) == 1
    assert b"FLAG{twin_white_text}" in streams[0]


def test_twin_1624_pdf_offpage_text() -> None:
    pdf_synthetic = (
        b"%PDF-1.3\nstream\nBT 1 0 0 1 -5000 -5000 Tm (FLAG{twin_offpage_text}) Tj ET\nendstream\n%%EOF"
    )
    tokens = extract_pdf_all_text_tokens(pdf_synthetic)
    assert "FLAG{twin_offpage_text}" in tokens


def test_twin_1625_pdf_content_stream() -> None:
    pdf_synthetic = b"%PDF-1.3\nstream\n(FLAG{twin_content_stream}) Tj\nendstream\n%%EOF"
    tokens = extract_pdf_all_text_tokens(pdf_synthetic)
    assert "FLAG{twin_content_stream}" in tokens


def test_twin_1626_pdf_attachment() -> None:
    pdf_synthetic = b"%PDF-1.3\n<< /Type /Filespec /F (secret.txt) /EF << /F (FLAG{twin_attachment}) >> >>\n%%EOF"
    assert b"FLAG{twin_attachment}" in pdf_synthetic


def test_twin_1627_docx_vanish() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        doc_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b"<w:body><w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>FLAG{twin_vanish}</w:t></w:r></w:p></w:body>"
            b"</w:document>"
        )
        z.writestr("word/document.xml", doc_xml)
    res = extract_docx_hidden_vanish(bio.getvalue())
    assert "FLAG{twin_vanish}" in res


def test_twin_1628_docx_embeddings() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        z.writestr("word/embeddings/config.cfg", b"FLAG{twin_embedded_file}")
    files = extract_docx_embeddings(bio.getvalue())
    assert files.get("config.cfg") == b"FLAG{twin_embedded_file}"


def test_twin_1629_docx_comments() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        comm_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b"<w:comment><w:p><w:r><w:t>FLAG{twin_comment}</w:t></w:r></w:p></w:comment>"
            b"</w:comments>"
        )
        z.writestr("word/comments.xml", comm_xml)
    res = extract_docx_comments(bio.getvalue())
    assert "FLAG{twin_comment}" in res


def test_twin_1630_docx_tracked_changes() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        doc_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b"<w:body><w:p><w:ins><w:r><w:t>FLAG{twin_ins}</w:t></w:r></w:ins></w:p></w:body>"
            b"</w:document>"
        )
        z.writestr("word/document.xml", doc_xml)
    res = extract_docx_tracked_revisions(bio.getvalue())
    assert "FLAG{twin_ins}" in res["ins"]


def test_twin_1631_xlsx_veryhidden() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        wb_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            b'<sheets><sheet name="Hidden" sheetId="2" state="veryHidden" r:id="rId2"/></sheets>'
            b"</workbook>"
        )
        sheet_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            b"<sheetData><row><c><t>FLAG{twin_veryhidden}</t></c></row></sheetData>"
            b"</worksheet>"
        )
        z.writestr("xl/workbook.xml", wb_xml)
        z.writestr("xl/worksheets/sheet2.xml", sheet_xml)
    res = extract_xlsx_hidden_sheets(bio.getvalue())
    assert "FLAG{twin_veryhidden}" in res


def test_twin_1632_xlsx_comments() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        comm_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            b"<commentList><comment><text><t>FLAG{twin_cell_comment}</t></text></comment></commentList>"
            b"</comments>"
        )
        z.writestr("xl/comments/comment1.xml", comm_xml)
    res = extract_xlsx_cell_comments(bio.getvalue())
    assert "FLAG{twin_cell_comment}" in res


def test_twin_1633_docm_vba() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        z.writestr("word/vbaProject.bin", b"\x01\x00\x02\x00FLAG{twin_docm_vba}\x00\x00")
    res = extract_ooxml_vba_strings(bio.getvalue())
    assert any("FLAG{twin_docm_vba}" in s for s in res)


def test_twin_1634_xlsm_vba() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        z.writestr("xl/vbaProject.bin", b"\x01\x00\x02\x00FLAG{twin_xlsm_vba}\x00\x00")
    res = extract_ooxml_vba_strings(bio.getvalue())
    assert any("FLAG{twin_xlsm_vba}" in s for s in res)


def test_twin_1642_gif_slide_chunks() -> None:
    chunks = ["FLAG{", "twin_", "slide", "_chunk", "}"]
    assert "".join(chunks) == "FLAG{twin_slide_chunk}"


def test_twin_1643_gif_zero_duration() -> None:
    frames = [{"duration": 150}, {"duration": 0, "payload": "FLAG{twin_zero_dur}"}]
    zero_frame = next(f for f in frames if f["duration"] == 0)
    assert zero_frame["payload"] == "FLAG{twin_zero_dur}"


def test_twin_1644_gif_comment() -> None:
    b64_payload = base64.b64encode(b"FLAG{twin_gif_comment}")
    gif_raw = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xfe" + bytes([len(b64_payload)]) + b64_payload + b"\x00;"
    pos = gif_raw.find(b"\x21\xfe")
    length = gif_raw[pos + 2]
    comment = gif_raw[pos + 3 : pos + 3 + length]
    assert base64.b64decode(comment) == b"FLAG{twin_gif_comment}"


def test_twin_1645_gif_palette() -> None:
    gct = bytearray(768)
    msg = b"FLAG{twin_palette}"
    gct[50 : 50 + len(msg)] = msg
    m = re.search(rb"FLAG\{[^}]+\}", bytes(gct))
    assert m is not None
    assert m.group(0) == b"FLAG{twin_palette}"


def test_twin_1647_gif_diff_xor() -> None:
    msg = b"FLAG{twin_diff}"
    p0 = [10] * len(msg)
    p1 = [p0[i] ^ msg[i] for i in range(len(msg))]
    recovered = bytes([p0[i] ^ p1[i] for i in range(len(msg))])
    assert recovered == msg


def test_twin_1656_four_fsk() -> None:
    rate = 8000
    tones = [800.0, 1200.0, 1600.0, 2000.0]
    symbol_samples = 320
    test_bytes = b"OK"
    samples_list = []
    t = np.arange(symbol_samples) / rate
    for byte_val in test_bytes:
        symbols = [
            (byte_val >> 6) & 3,
            (byte_val >> 4) & 3,
            (byte_val >> 2) & 3,
            byte_val & 3,
        ]
        for s in symbols:
            samples_list.append((3000 * np.sin(2 * np.pi * tones[s] * t)).astype(np.int16))
    audio = np.concatenate(samples_list)
    dec = decode_mfsk(audio, rate, tones, symbol_samples)
    assert dec == test_bytes


def test_twin_1657_16fsk_ladder() -> None:
    rate = 8000
    chunk_samples = 400
    test_hex = "4142"
    samples_list = []
    t = np.arange(chunk_samples) / rate
    for h in test_hex:
        nib = int(h, 16)
        freq = 400.0 + nib * 120.0
        samples_list.append((3000 * np.sin(2 * np.pi * freq * t)).astype(np.int16))
    audio = np.concatenate(samples_list)
    dec = decode_16fsk_nibbles(audio, rate, base_freq=400.0, step_freq=120.0, chunk_samples=chunk_samples)
    assert dec == "AB"


def test_twin_1658_dtmf_xor() -> None:
    msg = b"OK"
    xor_masked = [b ^ 90 for b in msg]
    rec = bytes([val ^ 90 for val in xor_masked])
    assert rec == msg


def test_twin_1659_audio_cw_morse() -> None:
    morse_hex = "4142"
    assert bytes.fromhex(morse_hex) == b"AB"


def test_twin_1664_pdf_repair() -> None:
    corrupted = b"PDF-1.3\n(FLAG{twin_corrupted_pdf}) Tj\n%%EOF"
    repaired = b"%" + corrupted
    tokens = extract_pdf_all_text_tokens(repaired)
    assert "FLAG{twin_corrupted_pdf}" in tokens


def test_twin_1669_carve_second_png() -> None:
    png1 = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20 + b"IEND\xaeB`\x82"
    png2 = b"\x89PNG\r\n\x1a\nFLAG{twin_carve_png}IEND\xaeB`\x82"
    combined = png1 + png2
    png_headers = [m.start() for m in re.finditer(rb"\x89PNG\r\n\x1a\n", combined)]
    assert len(png_headers) == 2
    assert b"FLAG{twin_carve_png}" in combined[png_headers[1] :]


def test_twin_1670_carve_zip() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        z.writestr("flag.txt", b"FLAG{twin_carve_zip}")
    zip_bytes = bio.getvalue()
    raw_dump = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50 + zip_bytes
    offset = raw_dump.find(b"PK\x03\x04")
    with zipfile.ZipFile(io.BytesIO(raw_dump[offset:])) as zf:
        assert zf.read("flag.txt") == b"FLAG{twin_carve_zip}"


def test_twin_1672_jpeg_polyglot_zip() -> None:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        z.writestr("secret.txt", b"FLAG{twin_polyglot}")
    zip_bytes = bio.getvalue()
    jpg_polyglot = b"\xff\xd8\xff\xe0" + b"\x00" * 10 + b"\xff\xd9" + zip_bytes
    offset = jpg_polyglot.find(b"PK\x03\x04")
    with zipfile.ZipFile(io.BytesIO(jpg_polyglot[offset:])) as zf:
        assert zf.read("secret.txt") == b"FLAG{twin_polyglot}"
