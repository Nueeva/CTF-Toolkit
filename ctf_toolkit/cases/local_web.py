"""Loopback Workbench for a single case workspace."""

from __future__ import annotations

import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

from .store import Workspace
from .web_api import MAX_JSON, MAX_UPLOAD, Response, dispatch, get_asset

CONTENT_SECURITY = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"


class CaseServer(ThreadingHTTPServer):
    def __init__(self, port: int, workspace: Workspace):
        super().__init__(("127.0.0.1", port), CaseHandler)
        self.workspace = workspace
        self.authority = f"127.0.0.1:{self.server_port}"
        self.origin = f"http://{self.authority}"


class CaseHandler(BaseHTTPRequestHandler):
    server: CaseServer

    def _send(self, response: Response) -> None:
        data = response.body
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY)
        if response.attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{response.attachment}"')
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _authorized(self) -> bool:
        if self.headers.get("Host") != self.server.authority:
            self._send(Response({"error": "Use the loopback URL printed by the Workbench"}, 400))
            return False
        if self.command == "POST" and self.headers.get("Origin") != self.server.origin:
            self._send(Response({"error": "The request must originate from this Workbench"}, 403))
            return False
        return True

    def do_GET(self) -> None:
        if not self._authorized():
            return
        target = urlsplit(self.path)
        if target.path == "/" or target.path.startswith("/assets/"):
            name = "index.html" if target.path == "/" else target.path.removeprefix("/assets/")
            try:
                asset, content_type = get_asset(name)
                self._send(Response(asset, content_type=content_type))
            except LookupError as exc:
                self._send(Response({"error": str(exc)}, 404))
            return
        if target.path.startswith("/api/"):
            try:
                query = dict(parse_qsl(target.query, max_num_fields=20))
            except ValueError as exc:
                self._send(Response({"error": str(exc)}, 400))
                return
            self._send(dispatch(self.server.workspace, "GET", target.path.removeprefix("/api/"), query, self.headers))
            return
        self._send(Response({"error": "Page was not found"}, 404))

    def do_POST(self) -> None:
        if not self._authorized():
            return
        target = urlsplit(self.path)
        if not target.path.startswith("/api/"):
            self._send(Response({"error": "Page was not found"}, 404))
            return
        path = target.path.removeprefix("/api/")
        limit = MAX_UPLOAD if path == "import" else MAX_JSON
        try:
            length = int(self.headers["Content-Length"])
        except (TypeError, ValueError):
            length = -1
        if self.headers.get("Transfer-Encoding") or length < 0:
            self._send(Response({"error": "A valid request length is required"}, 400))
        elif length > limit:
            label = "Browser uploads are limited to 8 MiB" if path == "import" else "Request is too large"
            self._send(Response({"error": label}, 413))
        else:
            self.connection.settimeout(30)
            try:
                body = self.rfile.read(length)
            except (OSError, TimeoutError):
                self._send(Response({"error": "Request did not finish"}, 408))
                return
            if len(body) != length:
                self._send(Response({"error": "Request body is incomplete"}, 400))
                return
            self._send(dispatch(self.server.workspace, "POST", path, {}, self.headers, body,
                                author=getpass.getuser()))


def serve(workspace: Workspace, port: int = 8081) -> None:
    if not 0 <= port <= 65535:
        raise ValueError("Port must be in the range 0–65535")
    with CaseServer(port, workspace) as server:
        print(f"CTF Toolkit Workbench · {server.origin}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
