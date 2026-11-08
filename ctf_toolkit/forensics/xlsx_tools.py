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
                found = re.findall(rb"(?:TECHCOMFEST\d*|COMPFEST\d*|GEMASTIK\d*|WRECKIT\d*|HOLOGY\d*|SLASHROOT\d*|GETSFLAG|CTFLEARN|picoCTF|SEKAI|HIDC\d*|ARA\d*|CHTB|HTB|THM|ASIS|DICE|HOPE|OOO|ARKAV|LACTF|ACTF|LKS|CTF|FLAG|CT)\{[^}]+\}", raw)
                for f in found:
                    flag_str = f.decode("utf-8", errors="ignore")
                    if flag_str not in flags:
                        flags.append(flag_str)
            except Exception:
                pass

        if flags:
            result["flags"] = ", ".join(flags)

    return result


def extract_xlsx_hidden_sheets(xlsx_data: bytes | io.BytesIO | str) -> list[str]:
    """Extract strings from worksheets marked with state='hidden' or state='veryHidden' in XLSX."""
    if isinstance(xlsx_data, (bytes, bytearray)):
        zf = zipfile.ZipFile(io.BytesIO(xlsx_data), "r")
    elif isinstance(xlsx_data, io.BytesIO):
        zf = zipfile.ZipFile(xlsx_data, "r")
    else:
        zf = zipfile.ZipFile(str(xlsx_data), "r")

    hidden_results: list[str] = []
    with zf:
        namelist = zf.namelist()
        if "xl/workbook.xml" in namelist:
            wb_xml = zf.read("xl/workbook.xml")
            hidden_sheet_ids = re.findall(rb'<sheet\b[^>]*state=["\'](?:hidden|veryHidden)["\'][^>]*r:id="([^"]+)"', wb_xml)
            if not hidden_sheet_ids:
                hidden_sheet_ids = re.findall(rb'<sheet\b[^>]*r:id="([^"]+)"[^>]*state=["\'](?:hidden|veryHidden)["\']', wb_xml)

            # Map r:id to target sheet file in xl/_rels/workbook.xml.rels
            target_files = []
            if "xl/_rels/workbook.xml.rels" in namelist:
                rels_xml = zf.read("xl/_rels/workbook.xml.rels")
                for sid in hidden_sheet_ids:
                    m = re.search(rb'<Relationship\b[^>]*Id="' + sid + rb'"[^>]*Target="([^"]+)"', rels_xml)
                    if m:
                        target = m.group(1).decode("utf-8").lstrip("/")
                        if not target.startswith("xl/"):
                            target = "xl/" + target
                        target_files.append(target)
            else:
                target_files = ["xl/worksheets/sheet2.xml"]

            for tfile in target_files:
                if tfile in namelist:
                    s_xml = zf.read(tfile)
                    texts = re.findall(rb"<t(?: [^>]*)?>(.*?)</t>", s_xml)
                    hidden_results.extend(t.decode("utf-8", errors="ignore") for t in texts)
    return hidden_results


def extract_xlsx_cell_comments(xlsx_data: bytes | io.BytesIO | str) -> list[str]:
    """Extract cell notes and comments from xl/comments/*.xml in XLSX."""
    if isinstance(xlsx_data, (bytes, bytearray)):
        zf = zipfile.ZipFile(io.BytesIO(xlsx_data), "r")
    elif isinstance(xlsx_data, io.BytesIO):
        zf = zipfile.ZipFile(xlsx_data, "r")
    else:
        zf = zipfile.ZipFile(str(xlsx_data), "r")

    comments: list[str] = []
    with zf:
        for name in zf.namelist():
            if "comments" in name and name.endswith(".xml"):
                c_xml = zf.read(name)
                texts = re.findall(rb"<t(?: [^>]*)?>(.*?)</t>", c_xml)
                comments.extend(t.decode("utf-8", errors="ignore") for t in texts)
    return comments


def extract_ooxml_vba_strings(data: bytes | io.BytesIO | str) -> list[str]:
    """Extract ASCII strings from vbaProject.bin in Macro-Enabled Office docs (.docm, .xlsm)."""
    if isinstance(data, (bytes, bytearray)):
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    elif isinstance(data, io.BytesIO):
        zf = zipfile.ZipFile(data, "r")
    else:
        zf = zipfile.ZipFile(str(data), "r")

    strings: list[str] = []
    with zf:
        for name in zf.namelist():
            if name.endswith("vbaProject.bin"):
                vba_raw = zf.read(name)
                found = re.findall(rb"[A-Za-z0-9_\{\}\-]{5,}", vba_raw)
                strings.extend(s.decode("latin-1", errors="ignore") for s in found)
    return strings
