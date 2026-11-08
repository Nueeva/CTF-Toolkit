from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


def extract_docx_metadata(target: str | bytes | io.BytesIO | Path) -> dict[str, str]:
    """Extract OOXML metadata (docProps/core.xml, docProps/app.xml, docProps/custom.xml) from DOCX/XLSX/PPTX."""
    metadata: dict[str, str] = {}
    if isinstance(target, (str, Path)):
        bio: io.BytesIO | str | Path = target
    elif isinstance(target, bytes):
        bio = io.BytesIO(target)
    else:
        bio = target

    try:
        with zipfile.ZipFile(bio, "r") as zf:
            for xml_name in ["docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"]:
                if xml_name in zf.namelist():
                    content = zf.read(xml_name)
                    try:
                        root = ET.fromstring(content)
                        for elem in root.iter():
                            tag = elem.tag.split("}")[-1]  # strip namespace
                            if elem.text and elem.text.strip():
                                metadata[tag] = elem.text.strip()
                                if tag == "creator":
                                    metadata["author"] = elem.text.strip()
                    except Exception:
                        text = content.decode("utf-8", errors="ignore")
                        for match in re.finditer(r"<[^:>]*:?([a-zA-Z0-9_]+)[^>]*>([^<]+)</", text):
                            tag, val = match.groups()
                            metadata[tag] = val.strip()
                            if tag == "creator":
                                metadata["author"] = val.strip()
    except Exception as e:
        metadata["error"] = str(e)

    return metadata
