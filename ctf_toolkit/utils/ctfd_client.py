from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from typing import Any


class CTFdClient:
    """Universal high-performance API client for CTFd and GetsFlag platform."""

    def __init__(self, base_url: str = "https://getsflag.com", timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cookie_jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        self.csrf_nonce: str = ""
        self.logged_in = False
        self.username: str = ""

    def _request(
        self,
        endpoint: str,
        data: bytes | dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        url = endpoint if endpoint.startswith("http") else f"{self.base_url}{endpoint}"
        req_headers = {
            "User-Agent": "CTF-Toolkit/4.2.0 (Hermes-Engine; Apexsions-V5)",
            "Accept": "application/json, text/html, */*",
        }
        if self.csrf_nonce:
            req_headers["CSRF-Token"] = self.csrf_nonce
        if headers:
            req_headers.update(headers)

        payload_bytes: bytes | None = None
        if data is not None:
            if isinstance(data, dict):
                if req_headers.get("Content-Type") == "application/json":
                    payload_bytes = json.dumps(data).encode("utf-8")
                else:
                    payload_bytes = urllib.parse.urlencode(data).encode("utf-8")
                    req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, bytes):
                payload_bytes = data
            elif isinstance(data, str):
                payload_bytes = data.encode("utf-8")

        req = urllib.request.Request(url, data=payload_bytes, headers=req_headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
                body = resp.read()
                resp_headers = dict(resp.headers)
                return status, body, resp_headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def fetch_csrf_token(self) -> str:
        """Extract csrfNonce from login page."""
        status, body, _ = self._request("/login")
        html = body.decode("utf-8", errors="ignore")
        m = re.search(r"csrfNonce['\":\s]+([a-f0-9]{32,64})", html)
        if m:
            self.csrf_nonce = m.group(1)
            return self.csrf_nonce
        m2 = re.search(r"name=['\"]nonce['\"][^>]+value=['\"]([a-f0-9]+)['\"]", html)
        if m2:
            self.csrf_nonce = m2.group(1)
            return self.csrf_nonce
        return ""

    def login(self, identifier: str, password: str) -> bool:
        """Authenticate against CTFd instance."""
        if not self.csrf_nonce:
            self.fetch_csrf_token()

        login_data = {
            "name": identifier,
            "password": password,
            "_submit": "Submit",
            "nonce": self.csrf_nonce,
        }
        status, body, headers = self._request(
            "/login",
            data=login_data,
            headers={"Referer": f"{self.base_url}/login"},
        )
        # Refresh CSRF from challenges or home
        st_ch, body_ch, _ = self._request("/challenges")
        html_ch = body_ch.decode("utf-8", errors="ignore")
        m = re.search(r"csrfNonce['\":\s]+([a-f0-9]{32,64})", html_ch)
        if m:
            self.csrf_nonce = m.group(1)

        if "login" not in headers.get("Location", "") and status in (200, 302):
            self.logged_in = True
            self.username = identifier
            return True
        return False

    def get_challenges(self) -> list[dict[str, Any]]:
        """Fetch list of all active CTF challenges."""
        status, body, _ = self._request(
            "/api/v1/challenges",
            headers={"Referer": f"{self.base_url}/challenges"},
        )
        if status == 200:
            try:
                res = json.loads(body.decode("utf-8"))
                return res.get("data", [])
            except Exception:
                pass
        return []

    def get_challenge_detail(self, challenge_id: int) -> dict[str, Any]:
        """Fetch detailed challenge schema, files, and description."""
        status, body, _ = self._request(
            f"/api/v1/challenges/{challenge_id}",
            headers={"Referer": f"{self.base_url}/challenges"},
        )
        if status == 200:
            try:
                res = json.loads(body.decode("utf-8"))
                return res.get("data", {})
            except Exception:
                pass
        return {}

    def submit_flag(self, challenge_id: int, flag: str) -> dict[str, Any]:
        """Submit a captured flag to CTFd instance."""
        data = {
            "challenge_id": challenge_id,
            "submission": flag.strip(),
        }
        status, body, _ = self._request(
            "/api/v1/challenges/attempt",
            data=data,
            headers={
                "Referer": f"{self.base_url}/challenges",
                "Content-Type": "application/json",
            },
        )
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return {"success": False, "status": status, "raw": body.decode("utf-8", errors="ignore")}

    def download_file(self, file_url_or_path: str) -> bytes:
        """Download challenge attachment file directly into memory."""
        rel_path = file_url_or_path
        if rel_path.startswith("http"):
            rel_path = re.sub(r"^https?://[^/]+", "", rel_path)
        status, body, _ = self._request(
            rel_path,
            headers={"Referer": f"{self.base_url}/challenges"},
        )
        if status == 200:
            return body
        return b""
