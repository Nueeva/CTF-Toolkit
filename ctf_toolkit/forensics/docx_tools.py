from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET


def extract_docx_metadata(docx_data: bytes | io.BytesIO | str) -> dict[str, str]:
    """Extract metadata, properties, and embedded flags from DOCX (OpenXML) document."""
    result: dict[str, str] = {}

    if isinstance(docx_data, str):
        zf = zipfile.ZipFile(docx_data, "r")
    elif isinstance(docx_data, bytes):
        zf = zipfile.ZipFile(io.BytesIO(docx_data), "r")
    else:
        zf = zipfile.ZipFile(docx_data, "r")

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

        # 2. Parse extended app properties (docProps/app.xml)
        if "docProps/app.xml" in namelist:
            try:
                xml_content = zf.read("docProps/app.xml")
                root = ET.fromstring(xml_content)
                for elem in root.iter():
                    tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                    if elem.text and elem.text.strip():
                        if tag_name not in result:
                            result[tag_name] = elem.text.strip()
            except Exception:
                pass

        # 3. Parse custom properties (docProps/custom.xml)
        if "docProps/custom.xml" in namelist:
            try:
                xml_content = zf.read("docProps/custom.xml")
                root = ET.fromstring(xml_content)
                for prop in root.iter():
                    tag = prop.tag.split("}")[-1] if "}" in prop.tag else prop.tag
                    if tag == "property":
                        pname = prop.attrib.get("name", "")
                        pval = "".join(prop.itertext()).strip()
                        if pname and pval:
                            result[f"custom_{pname}"] = pval
            except Exception:
                pass

        # 4. Check for comments (word/comments.xml)
        if "word/comments.xml" in namelist:
            try:
                xml_content = zf.read("word/comments.xml").decode("utf-8", errors="ignore")
                matches = re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml_content)
                if matches:
                    result["comments"] = " ".join(matches)
            except Exception:
                pass

        # 5. Search for flag pattern across all internal XML files
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
