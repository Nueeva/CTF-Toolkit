import io
import zipfile
from ctf_toolkit.forensics.xlsx_tools import extract_xlsx_metadata


def test_extract_xlsx_metadata():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "docProps/core.xml",
            b"""<?xml version="1.0" encoding="UTF-8"?>
            <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                               xmlns:dc="http://purl.org/dc/elements/1.1/">
                <dc:creator>Analyst</dc:creator>
                <dc:title>Financial Audit</dc:title>
            </cp:coreProperties>""",
        )
        zf.writestr(
            "xl/workbook.xml",
            b"""<?xml version="1.0" encoding="UTF-8"?>
            <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
                <sheets>
                    <sheet name="Sales" sheetId="1" state="visible"/>
                    <sheet name="Confidential" sheetId="2" state="hidden"/>
                </sheets>
            </workbook>""",
        )
        zf.writestr(
            "xl/worksheets/sheet2.xml",
            b"""<?xml version="1.0" encoding="UTF-8"?>
            <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
                <sheetData>
                    <row r="1"><c r="A1" t="inlineStr"><is><t>GETSFLAG{hidden_sheet_flag}</t></is></c></row>
                </sheetData>
            </worksheet>""",
        )

    res = extract_xlsx_metadata(buf.getvalue())
    assert res.get("creator") == "Analyst"
    assert res.get("title") == "Financial Audit"
    assert "Sales" in res.get("sheets", "")
    assert "Confidential (hidden)" in res.get("hidden_sheets", "")
    assert "GETSFLAG{hidden_sheet_flag}" in res.get("flags", "")
