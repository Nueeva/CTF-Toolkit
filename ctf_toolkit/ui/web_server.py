from __future__ import annotations

import inspect
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


def _coerce_param(raw: Any, param: inspect.Parameter) -> Any:
    """Convert a JSON-or-string argument into the type the solver expects."""
    ann = param.annotation
    ann_str = str(ann)

    if isinstance(raw, str):
        if raw.startswith("@"):
            path = Path(raw[1:]).expanduser()
            if not path.is_file():
                raise FileNotFoundError(f"argument {param.name!r}: no such file {path}")
            raw = path.read_bytes()
        elif len(raw) > 1 and raw[0] == "^":
            import base64
            raw = base64.b64decode(raw[1:])

    if isinstance(raw, bytes):
        if ann is str or ann_str == "str":
            return raw.decode("utf-8", errors="replace")
        return raw

    if ann is int or ann_str == "int":
        try:
            return int(raw, 0) if isinstance(raw, str) else int(raw)
        except (TypeError, ValueError):
            return raw
    if ann is float or ann_str == "float":
        try:
            return float(raw)
        except (TypeError, ValueError):
            return raw
    if ann is bool or ann_str == "bool":
        if isinstance(raw, str):
            return raw.lower() in ("1", "true", "yes", "y", "on")
        return bool(raw)

    return raw


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
        elif self.path == "/api/tools":
            from ctf_toolkit.ui.palette import build_tool_catalog
            catalog = build_tool_catalog()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            summary = []
            for t in catalog:
                try:
                    sig = inspect.signature(t["func"])
                    params = [
                        {
                            "n": prm.name,
                            "d": "" if prm.default is inspect.Parameter.empty else repr(prm.default)[:40],
                            "req": prm.default is inspect.Parameter.empty,
                        }
                        for prm in sig.parameters.values()
                        if prm.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
                    ]
                except (ValueError, TypeError):
                    params = []
                summary.append(
                    {
                        "name": t["name"],
                        "category": t["category"],
                        "module": t["module"],
                        "doc": (t.get("doc") or "").strip(),
                        "params": params,
                    }
                )
            self.wfile.write(json.dumps(summary).encode("utf-8"))
        elif self.path == "/api/patterns":
            payload = {
                "identify": [
                    {"name": n, "doc": ""}
                    for n in (
                        "identify_cipher_text",
                        "identify_hash_format",
                        "auto_decode_layers",
                        "caesar_bruteforce",
                        "xor_bruteforce_single",
                        "triage_data",
                        "solve_crypto_task",
                    )
                ]
            }
            self._send_json(payload)
        elif self.path == "/api/cheatsheets":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(get_web_cheatsheet()).encode("utf-8"))
        elif self.path == "/api/queue":
            from ctf_toolkit.ui.palette import build_tool_catalog
            by_cat: dict[str, list[str]] = {}
            for t in build_tool_catalog():
                top = t["category"].split(".")[0]
                by_cat.setdefault(top, []).append(t["name"])
            payload = {
                "categories": [
                    {"name": k, "tools": sorted(v), "count": len(v)}
                    for k, v in sorted(by_cat.items())
                ]
            }
            self._send_json(payload)
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
                temp_path = Path("/tmp/uploaded_ctf_artifact.bin")
                temp_path.write_bytes(body)
                res = AutoTriageDispatcher.dispatch_file(temp_path)
                self._send_json({"success": True, "data": res})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})

        elif self.path == "/api/call":
            try:
                payload = json.loads(body.decode("utf-8"))
                func_name = payload.get("function", "").strip()
                args_list = payload.get("args", [])
                kwargs_dict = payload.get("kwargs", {})

                from ctf_toolkit.ui.palette import build_tool_catalog
                catalog = build_tool_catalog()
                tool = next((t for t in catalog if t["name"] == func_name), None)
                if not tool:
                    self._send_json({"success": False, "error": f"Function '{func_name}' not found."})
                    return

                fn = tool["func"]
                sig = inspect.signature(fn)
                params = [p for p in sig.parameters.values() if p.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)]

                call_kwargs = {}
                pos_idx = 0
                for param in params:
                    if param.name in kwargs_dict:
                        raw_val = kwargs_dict[param.name]
                    elif pos_idx < len(args_list):
                        raw_val = args_list[pos_idx]
                        pos_idx += 1
                    elif param.default != inspect.Parameter.empty:
                        call_kwargs[param.name] = param.default
                        continue
                    else:
                        continue
                    call_kwargs[param.name] = _coerce_param(raw_val, param)

                res = fn(**call_kwargs)
                if isinstance(res, bytes):
                    res_val = {"hex": res.hex(), "utf8": res.decode("utf-8", errors="replace")}
                else:
                    res_val = res
                self._send_json({"success": True, "function": func_name, "result": res_val})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})

        elif self.path == "/api/flags":
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
                mgr = get_flag_manager()
                action = payload.get("action", "add")

                if action == "add":
                    name = (payload.get("name") or "").strip()
                    pattern = (payload.get("pattern") or "").strip()
                    priority = int(payload.get("priority", 50))
                    if not name or not pattern:
                        self._send_json({"success": False, "error": "name and pattern are required"})
                        return
                    import re as _re
                    _re.compile(pattern)
                    mgr.add_template(name, pattern, priority)
                    self._send_json({"success": True, "templates": mgr.templates})
                elif action == "remove":
                    name = (payload.get("name") or "").strip()
                    removed = mgr.remove_template(name)
                    self._send_json({"success": removed, "templates": mgr.templates})
                elif action == "reset":
                    mgr.reset_to_defaults()
                    self._send_json({"success": True, "templates": mgr.templates})
                else:
                    self._send_json({"success": False, "error": f"unknown action {action!r}"})
            except Exception as exc:  # noqa: BLE001
                self._send_json({"success": False, "error": str(exc)})

        elif self.path == "/api/flag/verify":
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
                candidate = (payload.get("candidate") or "").strip()
                mgr = get_flag_manager()
                hits = mgr.extract_flags(candidate)
                first = mgr.find_first_flag(candidate)
                self._send_json(
                    {
                        "success": True,
                        "accepted": bool(first),
                        "match": first,
                        "all_matches": hits,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                self._send_json({"success": False, "error": str(exc)})

        elif self.path == "/api/writeup/generate":
            try:
                payload = json.loads(body.decode("utf-8"))
                from ctf_toolkit.utils.writeup_generator import DynamicWriteupGenerator
                name = payload.get("name", "Challenge")
                cat = payload.get("category", "Crypto")
                flag = payload.get("flag", "")
                points = int(payload.get("points", 100))
                steps = payload.get("steps", [])

                output_folder = Path("/tmp/ctf_writeups")
                output_folder.mkdir(parents=True, exist_ok=True)
                wf, sf = DynamicWriteupGenerator.generate_writeup_and_solver(
                    challenge_name=name,
                    category=cat,
                    flag=flag,
                    steps=steps,
                    output_dir=output_folder,
                    points=points,
                )
                self._send_json({
                    "success": True,
                    "writeup_path": str(wf),
                    "solver_path": str(sf),
                    "writeup_md": wf.read_text(encoding="utf-8"),
                    "solver_py": sf.read_text(encoding="utf-8"),
                })
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
