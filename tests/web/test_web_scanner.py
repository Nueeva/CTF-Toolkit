from __future__ import annotations

import http.server
import threading
from ctf_toolkit.web.scanner import scan_web_target


class DummyCTFServer(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Debug-Trace", "b64:R0VUU0ZMQUd7aGVhZGVyX2xlYWtfb2t9")
            self.end_headers()
            self.wfile.write(b"<html><!-- Hidden: GETSFLAG{comment_leak_ok} --><body><h1>Challenge Landing</h1></body></html>")
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n# GETSFLAG{robots_txt_leak}\n")
        else:
            self.send_response(404)
            self.end_headers()


def test_scan_web_target_offline_instance() -> None:
    server = http.server.HTTPServer(("127.0.0.1", 0), DummyCTFServer)
    port = server.server_address[1]
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()

    try:
        url = f"http://127.0.0.1:{port}"
        res = scan_web_target(url, timeout=3.0)
        assert res["success"] is True
        flags = res["flags_found"]
        assert "GETSFLAG{header_leak_ok}" in flags
        assert "GETSFLAG{comment_leak_ok}" in flags
        assert "GETSFLAG{robots_txt_leak}" in flags
    finally:
        server.shutdown()
        server.server_close()
