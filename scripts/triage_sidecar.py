#!/usr/bin/env python3
"""
HTTP sidecar exposing the CTF-Toolkit forensic triage engine.

The production front end is a Rust binary that cannot host the Python
detectors, so it forwards raw uploads here. Bound to loopback only; nginx and
the Rust service are the sole ingress.

Protocol: POST /triage with the file bytes as the request body and the original
name in the X-Filename header.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctf_toolkit.triage.dispatcher import AutoTriageDispatcher  # noqa: E402
from ctf_toolkit.utils.flag_manager import get_flag_manager  # noqa: E402

MAX_UPLOAD = 40 * 1024 * 1024
ALLOWED_EXT = {
    ".pdf", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".odt",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff",
    ".wav", ".mp3", ".flac", ".ogg", ".m4a",
    ".pcap", ".pcapng", ".cap",
    ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".log", ".txt", ".csv", ".json", ".xml", ".evtx",
    ".bin", ".raw", ".dat", ".img", ".mem", ".dmp", ".core",
    ".elf", ".exe", ".so", ".py", ".js", ".php", ".html",
}


def _walk_strings(node, depth=0):
    if depth > 6:
        return
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_strings(v, depth + 1)
    elif isinstance(node, (list, tuple)):
        for v in node:
            yield from _walk_strings(v, depth + 1)


def _trim(node, depth=0):
    if depth > 5:
        return "..."
    if isinstance(node, dict):
        return {k: _trim(v, depth + 1) for k, v in list(node.items())[:40]}
    if isinstance(node, (list, tuple)):
        return [_trim(v, depth + 1) for v in list(node)[:40]]
    if isinstance(node, str):
        return node[:600]
    if isinstance(node, (bytes, bytearray)):
        return node[:200].hex()
    return node


def triage_bytes(data: bytes, filename: str) -> dict:
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXT:
        return {"ok": False, "error": f"unsupported extension: {ext or 'none'}"}
    if len(data) > MAX_UPLOAD:
        return {"ok": False, "error": "payload exceeds 40MB"}
    tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
    try:
        tmp.write(data)
        tmp.close()
        res = AutoTriageDispatcher.dispatch_file(tmp.name)
        flags = list(dict.fromkeys(res.get("flags_found", [])))
        findings = res.get("extracted_findings", {})
        for value in _walk_strings(findings):
            for hit in get_flag_manager().extract_flags(value):
                if hit["flag"] not in flags:
                    flags.append(hit["flag"])
        return {
            "ok": True,
            "filename": filename,
            "size": len(data),
            "specialists": res.get("dispatched_specialists", []),
            "flags": flags,
            "findings": _trim(findings),
        }
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "ctf-triage/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "online", "engine": "ctf-toolkit triage"})
        else:
            self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path != "/triage":
            self._send(404, {"ok": False, "error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                self._send(400, {"ok": False, "error": "empty body"})
                return
            if length > MAX_UPLOAD:
                self._send(413, {"ok": False, "error": "payload exceeds 40MB"})
                return
            name = unquote(self.headers.get("X-Filename", "upload.bin"))
            data = self.rfile.read(length)
            self._send(200, triage_bytes(data, name))
        except Exception as exc:
            self._send(500, {"ok": False, "error": str(exc),
                             "trace": traceback.format_exc()[-800:]})


if __name__ == "__main__":
    port = int(os.environ.get("TRIAGE_PORT", "8091"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    sys.stderr.write(f"triage sidecar listening on 127.0.0.1:{port}\n")
    srv.serve_forever()