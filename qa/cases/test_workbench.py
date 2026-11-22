from __future__ import annotations

import http.client
import json
import threading
import urllib.request
from contextlib import closing, contextmanager

import pytest

from ctf_toolkit.cases.demos import populate
from ctf_toolkit.cases.local_web import CaseServer
from ctf_toolkit.cases.operations import verify
from ctf_toolkit.cases.store import Workspace
from ctf_toolkit.cases.web_api import MAX_UPLOAD


@contextmanager
def browser_server(workspace):
    with CaseServer(0, workspace) as host:
        thread = threading.Thread(target=host.serve_forever, daemon=True)
        thread.start()
        try:
            yield host.origin
        finally:
            host.shutdown()
            thread.join(timeout=5)


def test_browser_upload_uses_original_file_bytes_and_applies_limits(tmp_path):
    workspace = Workspace.create(tmp_path)
    with browser_server(workspace) as base:
        headers = {"Origin": base, "Content-Type": "application/octet-stream",
                   "X-Artifact-Name": "catatan%20uji.bin"}
        binary = b"one line\n\x00\xff"
        request = urllib.request.Request(base + "/api/import", data=binary, headers=headers)
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 201
            artifact = json.load(response)
        assert artifact["label"] == "catatan uji.bin"
        assert workspace.blob(artifact) == binary

        with closing(http.client.HTTPConnection(base.removeprefix("http://"), timeout=10)) as conn:
            conn.putrequest("POST", "/api/import")
            for header, value in headers.items():
                conn.putheader(header, value)
            conn.putheader("Content-Length", str(MAX_UPLOAD + 1))
            conn.endheaders()
            assert conn.getresponse().status == 413
        assert len(workspace.snapshot()["artifacts"]) == 1


def test_local_chromium_investigation_and_reload(tmp_path):
    api = pytest.importorskip("playwright.sync_api")
    workspace = Workspace.create(tmp_path, "Exhibit")
    exhibit, = populate(workspace, "layered")
    with browser_server(workspace) as origin, api.sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch()
        except api.Error as exc:
            if "Executable doesn't exist" in str(exc):
                pytest.skip("Playwright Chromium is not installed")
            raise
        with closing(browser):
            page = browser.new_page(viewport={"width": 1376, "height": 980})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(origin, wait_until="domcontentloaded")
            api.expect(page.locator("#artifact-name")).to_have_text("exhibit.png")
            page.get_by_role("button", name="Run triage").click()
            member = page.get_by_role("button", name="desk/message.b64", exact=True)
            member_id = member.get_attribute("data-artifact")
            member_url = f"{origin}/api/artifact/{member_id}?offset=0"
            paused_member = []
            page.route(member_url, lambda route: paused_member.append(route))
            with page.expect_request(member_url):
                member.click()
            preview = page.get_by_role("button", name="Preview steps")
            api.expect(preview).to_be_disabled()
            assert len(paused_member) == 1
            paused_member.pop().continue_()
            page.unroute(member_url)
            preview.click()
            api.expect(page.locator("#recipe-result")).to_contain_text("hello")
            page.get_by_role("button", name="Save branch").click()
            api.expect(page.locator("#artifact-name")).to_have_text("b64d output")
            page.get_by_role("button", name="Trace source").click()
            api.expect(page.locator("#byte-data mark")).to_have_count(4)
            view = page.locator("#artifact-name")
            api.expect(view).to_have_text("desk/message.b64")
            page.get_by_role("button", name="Bookmark").click()
            page.get_by_role("textbox", name="Note text").fill("Base64 characters selected")
            page.get_by_role("button", name="Save note").click()
            api.expect(page.locator("#note-list")).to_contain_text("Base64 characters selected")

            artifact_url = f"{origin}/api/artifact/{exhibit['id']}?offset=0"
            paused = []
            page.route(artifact_url, lambda route: paused.append(route))
            with page.expect_request(artifact_url):
                page.reload(wait_until="domcontentloaded")
            page.get_by_role("button", name="Notes", exact=True).click()
            assert len(paused) == 1
            paused.pop().continue_()
            page.unroute(artifact_url)
            api.expect(page.locator("#artifact-name")).to_have_text("exhibit.png")
            api.expect(page.locator("#note-list")).to_be_visible()
            api.expect(page.locator("#note-list")).to_contain_text("Base64 characters selected")
            page.get_by_role("button", name="desk/message.b64 · bytes 0–4").click()
            api.expect(page.locator("#byte-data mark")).to_have_count(4)
            page.set_viewport_size({"width": 397, "height": 860})
            assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
            page.locator(".activity summary").click()
            api.expect(page.locator("#history")).to_contain_text("Note saved")
            page.get_by_role("button", name="Clear activity").click()
            api.expect(page.locator("#history li")).to_have_count(0)
            assert not errors
    assert verify(Workspace(tmp_path), replay=True)["replayed_runs"] == 2
