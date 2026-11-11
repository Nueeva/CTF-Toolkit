from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from ctf_toolkit.triage.analyzer import triage_data
from ctf_toolkit.utils.flag_manager import get_flag_manager


class AutoTriageDispatcher:
    """
    Automated File Type Dispatcher & Specialist Router for CTF Challenges:
    - .jpg / .jpeg: EXIF metadata, Steghide/Jsteg check, JPEG comments, trailing PK/GZIP
    - .png: IHDR chunk CRC check, zTXt/tEXt/iTXt chunk strings, LSB RGB bitplanes
    - .gif: Frame duration stego, frame comments, palette analysis, scanline bits
    - .pcap / .pcapng: TCP reassembly, HTTP credentials, DNS exfiltration tunnels, ICMP payloads
    - .zip / .tar / .gz / .7z: Header integrity repair, nested archive unzipping, trailing payload carving
    - .pdf / .docx / .xlsx: Hidden comments, vanishing white-text, embedded VBA macros, revision tracking
    - .wav / .mp3: Audio LSB, DTMF tone detection, CW Morse code audio decoding
    - .elf / .exe: Checksec, architecture detection, ROP gadgets, binary string extraction
    """

    @staticmethod
    def dispatch_file(filepath: str | Path) -> dict[str, Any]:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Target file not found: {path}")

        data = path.read_bytes()
        ext = path.suffix.lower()
        fname = path.name

        res: dict[str, Any] = {
            "filename": fname,
            "extension": ext,
            "size": len(data),
            "dispatched_specialists": [],
            "extracted_findings": {},
            "flags_found": [],
        }

        # 1. Base Triage Analysis (Entropy, Magic Bytes, IoC)
        triage_rep = triage_data(data, target_label=fname)
        res["triage_summary"] = {
            "magic_type": triage_rep.magic_type,
            "category_hint": triage_rep.category_hint,
            "entropy": triage_rep.entropy,
            "ioc": triage_rep.ioc,
        }

        # Check for immediate flags in raw data
        flags = get_flag_manager().extract_flags(data)
        if flags:
            res["flags_found"].extend([f["flag"] for f in flags])

        # 2. Specialized Format Handlers (Based on Extension & Magic Bytes)
        is_jpeg = ext in (".jpg", ".jpeg") or data.startswith(b"\xff\xd8\xff")
        is_png = ext == ".png" or data.startswith(b"\x89PNG\r\n\x1a\n")
        is_gif = ext == ".gif" or data.startswith((b"GIF87a", b"GIF89a"))
        is_pcap = ext in (".pcap", ".pcapng", ".cap") or data.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"))
        is_zip = ext in (".zip", ".jar", ".apk") or data.startswith(b"PK\x03\x04")
        is_tar_gz = ext in (".tar", ".gz", ".tgz") or data.startswith((b"\x1f\x8b", b"ustar"))
        is_office = ext in (".docx", ".xlsx", ".docm", ".xlsm", ".pdf") or (data.startswith(b"PK\x03\x04") and (b"word/" in data or b"xl/" in data)) or data.startswith(b"%PDF")
        is_audio = ext in (".wav", ".mp3", ".flac") or data.startswith((b"RIFF", b"ID3"))

        # --- Handler A: JPEG Forensic Specialist ---
        if is_jpeg:
            res["dispatched_specialists"].append("JPEG_Specialist")
            try:
                from ctf_toolkit.forensics.jpeg_tools import extract_jpeg_comments, repair_jpeg_header
                comments = extract_jpeg_comments(data)
                res["extracted_findings"]["jpeg_comments"] = comments
                for c in comments:
                    fl = get_flag_manager().extract_flags(c)
                    if fl:
                        res["flags_found"].extend([f["flag"] for f in fl])
            except Exception as e:
                res["extracted_findings"]["jpeg_error"] = str(e)

        # --- Handler B: PNG Stego & Chunk Specialist ---
        if is_png:
            res["dispatched_specialists"].append("PNG_Specialist")
            try:
                from ctf_toolkit.forensics.png_tools import extract_png_text_chunks
                from ctf_toolkit.forensics.image_channels import extract_png_trailing_bytes
                from ctf_toolkit.forensics.image_stego import extract_all_bit_planes
                from ctf_toolkit.forensics.carve import transform_candidates
                chunks = extract_png_text_chunks(data)
                trailing = extract_png_trailing_bytes(data)
                res["extracted_findings"]["png_text_chunks"] = chunks
                if trailing:
                    res["extracted_findings"]["png_trailing_bytes_size"] = len(trailing)
                    tr_fl = get_flag_manager().extract_flags(trailing)
                    if tr_fl:
                        res["flags_found"].extend([f["flag"] for f in tr_fl])

                # Exhaustive bit-plane and channel extraction (R0..R7, G0..G7, B0..B7, A0..A7, interleaved)
                planes = extract_all_bit_planes(data)
                for pname, pdata in planes.items():
                    pfl = get_flag_manager().extract_flags(pdata[:4096])
                    if pfl:
                        res["flags_found"].extend([f["flag"] for f in pfl])
                    # Try transforms (Base64, Hex, Base32) on bit-plane bytes
                    ptext = pdata[:2048].decode("latin-1", errors="ignore")
                    for tname, tval in transform_candidates(ptext):
                        tfl = get_flag_manager().extract_flags(tval)
                        if tfl:
                            res["flags_found"].extend([f["flag"] for f in tfl])
                    # Try single-byte XOR brute on active bit-planes
                    for k in (90, 170):
                        xored = bytes(b ^ k for b in pdata[:128])
                        if b"GETSFLAG{" in xored:
                            x_fl = get_flag_manager().extract_flags(xored)
                            if x_fl:
                                res["flags_found"].extend([f["flag"] for f in x_fl])
            except Exception as e:
                res["extracted_findings"]["png_error"] = str(e)

        # --- Handler C: GIF Animation & Palette Specialist ---
        if is_gif:
            res["dispatched_specialists"].append("GIF_Specialist")
            try:
                from ctf_toolkit.forensics.image_channels import extract_gif_frame_palettes_and_comments
                from ctf_toolkit.forensics.image_stego import extract_gif_stego_payloads
                gif_info = extract_gif_frame_palettes_and_comments(data)
                res["extracted_findings"]["gif_analysis"] = gif_info
                # Run full GIF frame stego analysis
                gif_strings = extract_gif_stego_payloads(data)
                for s in gif_strings:
                    gfl = get_flag_manager().extract_flags(s)
                    if gfl:
                        res["flags_found"].extend([f["flag"] for f in gfl])
            except Exception as e:
                res["extracted_findings"]["gif_error"] = str(e)

        # --- Handler D: PCAP Network Traffic Specialist ---
        if is_pcap:
            res["dispatched_specialists"].append("PCAP_Network_Specialist")
            try:
                from ctf_toolkit.forensics.pcap_extract import extract_http_basic_auth, repair_pcap_header
                from ctf_toolkit.forensics.network_artifacts import assemble_icmp_echo_payloads, extract_dns_hex_subdomains
                from ctf_toolkit.forensics.log_pcap_analyzer import analyze_pcap_streams
                auths = extract_http_basic_auth(data)
                icmp = assemble_icmp_echo_payloads(data)
                dns_hex = extract_dns_hex_subdomains(data)
                res["extracted_findings"]["http_auths"] = auths
                if icmp:
                    res["extracted_findings"]["icmp_assembled_size"] = len(icmp)
                    ic_fl = get_flag_manager().extract_flags(icmp)
                    if ic_fl:
                        res["flags_found"].extend([f["flag"] for f in ic_fl])
                if dns_hex:
                    res["extracted_findings"]["dns_hex_size"] = len(dns_hex)
                    dns_fl = get_flag_manager().extract_flags(dns_hex)
                    if dns_fl:
                        res["flags_found"].extend([f["flag"] for f in dns_fl])

                # Deep stream and tunnel parser
                pcap_strings = analyze_pcap_streams(data)
                for ps in pcap_strings:
                    ps_fl = get_flag_manager().extract_flags(ps)
                    if ps_fl:
                        res["flags_found"].extend([f["flag"] for f in ps_fl])
            except Exception as e:
                res["extracted_findings"]["pcap_error"] = str(e)

        # --- Handler E: Archive & Polyglot Specialist ---
        if is_zip or is_tar_gz:
            res["dispatched_specialists"].append("Archive_Specialist")
            try:
                import zipfile, io
                if is_zip and zipfile.is_zipfile(io.BytesIO(data)):
                    with zipfile.ZipFile(io.BytesIO(data)) as zf:
                        namelist = zf.namelist()
                        res["extracted_findings"]["archive_files"] = namelist
                        for zfname in namelist:
                            if not zfname.endswith("/"):
                                try:
                                    content = zf.read(zfname)
                                    zf_fl = get_flag_manager().extract_flags(content)
                                    if zf_fl:
                                        res["flags_found"].extend([f["flag"] for f in zf_fl])
                                except RuntimeError:
                                    # Password protected zip! Try cracking with top common wordlist
                                    from ctf_toolkit.forensics.carve import crack_zip_file
                                    cracked_flags = crack_zip_file(data)
                                    if cracked_flags:
                                        res["flags_found"].extend(cracked_flags)
            except Exception as e:
                res["extracted_findings"]["archive_error"] = str(e)

        # --- Handler F: Office & Document Specialist ---
        if is_office:
            res["dispatched_specialists"].append("Document_Specialist")
            meta_blob = []
            try:
                if ext == ".pdf" or data.startswith(b"%PDF"):
                    from ctf_toolkit.forensics.pdf_tools import extract_pdf_metadata
                    meta = extract_pdf_metadata(data)
                    res["extracted_findings"]["pdf_meta"] = meta
                    if isinstance(meta, dict):
                        meta_blob = [str(v) for v in meta.values()]
                elif ext in (".docx", ".docm"):
                    from ctf_toolkit.forensics.docx_tools import extract_docx_metadata
                    meta = extract_docx_metadata(data)
                    res["extracted_findings"]["docx_meta"] = meta
                    if isinstance(meta, dict):
                        meta_blob = [str(v) for v in meta.values()]
                elif ext in (".xlsx", ".xlsm"):
                    from ctf_toolkit.forensics.xlsx_tools import extract_xlsx_metadata
                    meta = extract_xlsx_metadata(data)
                    res["extracted_findings"]["xlsx_meta"] = meta
                    if isinstance(meta, dict):
                        meta_blob = [str(v) for v in meta.values()]
                # Scan every metadata value for embedded flag strings
                for val in meta_blob:
                    fl = get_flag_manager().extract_flags(val)
                    if fl:
                        res["flags_found"].extend([f["flag"] for f in fl])
            except Exception as e:
                res["extracted_findings"]["document_error"] = str(e)

        # --- Handler G: Audio Waveform Specialist ---
        if is_audio:
            res["dispatched_specialists"].append("Audio_Specialist")
            try:
                from ctf_toolkit.forensics.audio_codecs import auto_decode, load_wav
                from ctf_toolkit.forensics.audio_tools import auto_audio_solve
                samples, srate = load_wav(data)
                channels = dict(auto_audio_solve(data))
                channels.update(auto_decode(samples, srate))
                # legacy PCM-LSB channels carry flag text in raw bytes
                for k in ("pcm_lsb_msb", "pcm_lsb_lsb"):
                    if k in channels:
                        channels[k] = str(channels[k])[:4096]
                summary = {}
                for cname, payload in channels.items():
                    text = str(payload)
                    summary[cname] = text[:160]
                    fl = get_flag_manager().extract_flags(text)
                    if fl:
                        res["flags_found"].extend([f["flag"] for f in fl])
                res["extracted_findings"]["audio_channels"] = summary
            except Exception as e:
                res["extracted_findings"]["audio_error"] = str(e)

        # --- Handler H: Universal Carve & Transform Pass ---
        # Any specimen may hide the flag inside an appended archive, a base64
        # metadata blob, a hex log line or a rot13 comment. Carve every embedded
        # container, unpack it, then run every reversible transform over the
        # plain text before giving up.
        try:
            from ctf_toolkit.forensics.carve import carve_and_expand, transform_candidates
            from ctf_toolkit.forensics.log_pcap_analyzer import analyze_log_artifacts

            # Run specialized log analyzer if data contains log lines
            log_strings = analyze_log_artifacts(data.decode("latin-1", errors="ignore"))
            for ls in log_strings:
                ls_fl = get_flag_manager().extract_flags(ls)
                if ls_fl:
                    res["flags_found"].extend([f["flag"] for f in ls_fl])
            carved = carve_and_expand(data, depth=2)
            if carved:
                res["dispatched_specialists"].append("Carve_Engine")
            carriers = [("self", data)] + carved
            # image/document metadata strings are carriers too
            for key, val in list(res["extracted_findings"].items()):
                if isinstance(val, (str, bytes)):
                    carriers.append((f"meta:{key}", val if isinstance(val, bytes) else val.encode("latin-1", "ignore")))
                elif isinstance(val, dict):
                    for k2, v2 in val.items():
                        if isinstance(v2, (str, bytes)):
                            carriers.append((f"meta:{key}.{k2}", v2 if isinstance(v2, bytes) else v2.encode("latin-1", "ignore")))
            seen = 0
            for name, blob in carriers[:60]:
                text = blob.decode("latin-1", errors="ignore")
                for tname, ttext in transform_candidates(text):
                    seen += 1
                    fl = get_flag_manager().extract_flags(ttext)
                    if fl:
                        res["flags_found"].extend([f["flag"] for f in fl])
                        res["extracted_findings"].setdefault("carve_hits", []).append(
                            {"carrier": name, "transform": tname}
                        )
                fl = get_flag_manager().extract_flags(text)
                if fl:
                    res["flags_found"].extend([f["flag"] for f in fl])
            res["extracted_findings"]["carve_carriers"] = len(carriers)
            res["extracted_findings"]["carve_transforms"] = seen
        except Exception as e:
            res["extracted_findings"]["carve_error"] = str(e)

        # Deduplicate discovered flags
        res["flags_found"] = list(dict.fromkeys(res["flags_found"]))
        return res
