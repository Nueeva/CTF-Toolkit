from __future__ import annotations

import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from ctf_toolkit.crypto.auto_solver import solve_crypto_task
from ctf_toolkit.crypto.cipher_id import identify_cipher_text, identify_hash_format
from ctf_toolkit.triage.dispatcher import AutoTriageDispatcher
from ctf_toolkit.utils.flag_manager import get_flag_manager
from ctf_toolkit.web.cheatsheets import get_web_cheatsheet


HTML_PAGE = """<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTF-Toolkit Workbench · CyberChef Style</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #c9d1d9;
    --accent: #58a6ff; --green: #3fb950; --red: #f85149; --card: #21262d;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
  body { background: var(--bg); color: var(--text); padding: 20px; font-size: 14px; }
  header { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }
  h1 { font-size: 20px; font-weight: 700; color: #fff; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }
  h2 { font-size: 15px; margin-bottom: 12px; color: var(--accent); }
  textarea, input { width: 100%; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px; color: #fff; font-family: 'JetBrains Mono', monospace; font-size: 13px; margin-bottom: 12px; }
  textarea { min-height: 120px; resize: vertical; }
  .btn { background: #238636; color: #fff; border: 0; border-radius: 6px; padding: 8px 16px; cursor: pointer; font-weight: 600; font-size: 13px; }
  .btn:hover { background: #2ea043; }
  .btn-sec { background: var(--card); border: 1px solid var(--border); margin-left: 8px; }
  .btn-sec:hover { background: #30363d; }
  pre { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px; font-family: 'JetBrains Mono', monospace; font-size: 12.5px; overflow-x: auto; color: #7ee787; min-height: 80px; }
  .badge { display: inline-block; background: #1f6feb26; color: var(--accent); border: 1px solid #1f6feb; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-weight: 600; margin-bottom: 8px; }
</style>
</head>
<body>
<header>
  <div>
    <h1>CTF-Toolkit Web Workbench</h1>
    <p style="color:#8b949e;font-size:13px">CyberChef-Style Visual Analyzer, Auto-Solver & File Triage</p>
  </div>
  <span class="badge">v4.2.0 • Headless / Standalone</span>
</header>

<div class="grid">
  <!-- Left Panel: Text & Prompt Analyzer -->
  <div class="card">
    <h2>⚡ Text / Cipher / Prompt Auto-Solver</h2>
    <textarea id="promptInput" placeholder="Paste deskripsi challenge, ciphertext (Base64, Hex, Morse, A1Z26), atau RSA params (p, q, e, c)..."></textarea>
    <button class="btn" onclick="solveText()">Run Auto-Solver</button>
    <button class="btn btn-sec" onclick="identifyText()">Identify Cipher / Hash</button>
    <h2 style="margin-top:16px">Analysis & Flag Output</h2>
    <pre id="textOutput">// Output hasil analisa akan muncul di sini</pre>
  </div>

  <!-- Right Panel: File Upload & Forensic Specialist -->
  <div class="card">
    <h2>📁 Intelligent File Triage (Format Dispatcher)</h2>
    <p style="color:#8b949e;margin-bottom:12px;font-size:12.5px">Upload file apa pun (.jpg, .png, .gif, .pcap, .zip, .pdf, .docx, .wav). Toolkit otomatis mengarahkan ke specialist yang tepat.</p>
    <input type="file" id="fileInput">
    <button class="btn" onclick="uploadAndTriage()">Upload & Analyze File</button>
    <h2 style="margin-top:16px">Specialist Findings</h2>
    <pre id="fileOutput">// Hasil ekstraksi file forensics / artifacts</pre>
  </div>
</div>

<script>
async function solveText() {
  const text = document.getElementById('promptInput').value;
  const res = await fetch('/api/solve', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text})
  });
  const data = await res.json();
  document.getElementById('textOutput').innerText = JSON.stringify(data, null, 2);
}

async function identifyText() {
  const text = document.getElementById('promptInput').value;
  const res = await fetch('/api/identify', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text})
  });
  const data = await res.json();
  document.getElementById('textOutput').innerText = JSON.stringify(data, null, 2);
}

async function uploadAndTriage() {
  const fileInput = document.getElementById('fileInput');
  if (!fileInput.files.length) { alert('Pilih file terlebih dahulu!'); return; }
  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append('file', file);
  
  const res = await fetch('/api/triage_file', {
    method: 'POST',
    body: formData
  });
  const data = await res.json();
  document.getElementById('fileOutput').innerText = JSON.stringify(data, null, 2);
}
</script>
</body>
</html>
"""


class WorkbenchHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        elif self.path == "/api/flags":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            templates = get_flag_manager().templates
            self.wfile.write(json.dumps(templates).encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        if self.path == "/api/solve":
            try:
                payload = json.loads(body.decode("utf-8"))
                text = payload.get("text", "")
                flag = solve_crypto_task(text)
                ciphers = identify_cipher_text(text)
                self._send_json({
                    "success": True,
                    "flag_captured": flag,
                    "characteristics": ciphers,
                })
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})

        elif self.path == "/api/identify":
            try:
                payload = json.loads(body.decode("utf-8"))
                text = payload.get("text", "")
                hashes = identify_hash_format(text)
                ciphers = identify_cipher_text(text)
                self._send_json({
                    "success": True,
                    "hashes": hashes,
                    "cipher_analysis": ciphers,
                })
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})

        elif self.path == "/api/triage_file":
            try:
                # Handle raw binary or multipart upload
                temp_path = Path("/tmp/uploaded_ctf_artifact.bin")
                temp_path.write_bytes(body)
                res = AutoTriageDispatcher.dispatch_file(temp_path)
                self._send_json({"success": True, "data": res})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})
        else:
            self.send_error(404, "Endpoint not found")

    def _send_json(self, data: dict[str, Any], status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))


def start_workbench_server(port: int = 8080) -> None:
    """Start local standalone CyberChef-style web interface."""
    server = HTTPServer(("0.0.0.0", port), WorkbenchHTTPHandler)
    print(f"[*] CTF-Toolkit Web Workbench running at http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[!] Stopping web server...")
        server.server_close()
