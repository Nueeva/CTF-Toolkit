from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET


def extract_xlsx_metadata(xlsx_data: bytes | io.BytesIO | str) -> dict[str, str]:
    """Extract metadata, sheet names, hidden sheets, shared strings, and embedded flags from XLSX workbook."""
    result: dict[str, str] = {}

    if isinstance(xlsx_data, str):
        zf = zipfile.ZipFile(xlsx_data, "r")
    elif isinstance(xlsx_data, bytes):
        zf = zipfile.ZipFile(io.BytesIO(xlsx_data), "r")
    else:
        zf = zipfile.ZipFile(xlsx_data, "r")

    with zf:
        namelist = zf.namelist()

        # 1. Parse core properties (docProps/core.xml)
        if "docProps/core.xml" in namelist:
            try:
                xml_content = zf.read("docProps/core.xml")
                root = ET.fromstring(xml_content)
                for elem in root.iter():
                    tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                    if elem.text and elem.text.strip():
                        result[tag_name] = elem.text.strip()
            except Exception:
                pass

        # 2. Parse workbook structure & sheet visibility (xl/workbook.xml)
        if "xl/workbook.xml" in namelist:
            try:
                xml_content = zf.read("xl/workbook.xml")
                root = ET.fromstring(xml_content)
                sheets = []
                hidden_sheets = []
                for sheet in root.iter():
                    tag = sheet.tag.split("}")[-1] if "}" in sheet.tag else sheet.tag
                    if tag == "sheet":
                        name = sheet.attrib.get("name", "")
                        state = sheet.attrib.get("state", "visible")
                        if state in ("hidden", "veryHidden"):
                            hidden_sheets.append(f"{name} ({state})")
                        sheets.append(name)
                if sheets:
                    result["sheets"] = ", ".join(sheets)
                if hidden_sheets:
                    result["hidden_sheets"] = ", ".join(hidden_sheets)
            except Exception:
                pass

        # 3. Parse shared strings table (xl/sharedStrings.xml)
        if "xl/sharedStrings.xml" in namelist:
            try:
                xml_content = zf.read("xl/sharedStrings.xml")
                root = ET.fromstring(xml_content)
                strings = []
                for t in root.iter():
                    tag = t.tag.split("}")[-1] if "}" in t.tag else t.tag
                    if tag == "t" and t.text and t.text.strip():
                        strings.append(t.text.strip())
                if strings:
                    result["shared_strings"] = " | ".join(strings[:20])
            except Exception:
                pass

        # 4. Search for flag pattern across all internal XML files
        flags: list[str] = []
        for name in namelist:
            try:
                raw = zf.read(name)
                found = re.findall(rb"(?:GETSFLAG|CT)\{[^}]+\}", raw)
                for f in found:
                    flag_str = f.decode("utf-8", errors="ignore")
                    if flag_str not in flags:
                        flags.append(flag_str)
            except Exception:
                pass

        if flags:
            result["flags"] = ", ".join(flags)

    return result
