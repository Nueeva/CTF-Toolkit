import io
import zipfile
from ctf_toolkit.forensics.docx_tools import extract_docx_metadata


def test_docx_metadata_extraction():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        core_xml = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>Secret Proposal</dc:title>
    <dc:creator>Agent007</dc:creator>
    <cp:keywords>GETSFLAG{test_docx_flag}</cp:keywords>
</cp:coreProperties>"""
        z.writestr("docProps/core.xml", core_xml)
        z.writestr("word/document.xml", b"<w:document><w:body><w:p><w:r><w:t>Hello World</w:t></w:r></w:p></w:body></w:document>")

    buf.seek(0)
    meta = extract_docx_metadata(buf.getvalue())
    assert meta.get("title") == "Secret Proposal"
    assert meta.get("creator") == "Agent007"
    assert meta.get("keywords") == "GETSFLAG{test_docx_flag}"
    assert "GETSFLAG{test_docx_flag}" in meta.get("flags", "")
