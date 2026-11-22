from __future__ import annotations

import ipaddress
import secrets
import socket
import statistics
import threading
import time
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from ctf_toolkit.cases import exchange
from ctf_toolkit.cases.notes import save_note
from ctf_toolkit.cases.store import Workspace, new_id
from ctf_toolkit.cases.team_host import configure


def _local_certificate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    private = directory / "test-private.pem"
    public = directory / "test-cert.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    public.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return public, private


@contextmanager
def running_team(directory):
    pytest.importorskip("django")
    uvicorn = pytest.importorskip("uvicorn")
    from django.core.management import call_command

    socket_obj = socket.socket()
    with closing(socket_obj):
        socket_obj.bind(("127.0.0.1", 0))
        socket_obj.listen(32)
        port = socket_obj.getsockname()[1]
        origin = f"https://127.0.0.1:{port}"
        configure(directory, origin, secrets.token_urlsafe(64))
        call_command("migrate", interactive=False, verbosity=0)
        from django.core.asgi import get_asgi_application

        cert, key = _local_certificate(directory)
        config = uvicorn.Config(get_asgi_application(), host="127.0.0.1", port=port,
                                ssl_certfile=str(cert), ssl_keyfile=str(key), lifespan="off",
                                access_log=False, log_level="error", timeout_graceful_shutdown=3)
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, kwargs={"sockets": [socket_obj]}, daemon=True)
        thread.start()
        try:
            end = time.monotonic() + 15
            while not server.started and thread.is_alive() and time.monotonic() < end:
                time.sleep(0.03)
            assert server.started
            yield origin
        finally:
            server.should_exit = True
            thread.join(timeout=15)


def establish(page, origin, username, password):
    page.goto(origin + "/login/", wait_until="domcontentloaded")
    page.get_by_label("Username", exact=True).fill(username)
    page.get_by_label("Password", exact=True).fill(password)
    page.get_by_role("button", name="Sign in").click()
    page.wait_for_url(origin + "/")


def post(context, origin, url, data, headers=None):
    cookie = next(item["value"] for item in context.cookies() if item["name"] == "csrftoken")
    return context.request.post(url, data=data, headers={"Origin": origin, "X-CSRFToken": cookie, **(headers or {})})


def test_private_host_review_reconnect_and_conflicts_in_five_browser_sessions(tmp_path):
    api = pytest.importorskip("playwright.sync_api")
    with running_team(tmp_path) as origin:
        from django.contrib.auth import get_user_model
        from ctf_toolkit.cases.team_app.models import Case, Membership

        case_id = new_id()
        workspace = Workspace.create(tmp_path / "cases" / case_id, "Shared exhibit", case_id=case_id)
        hidden_id = new_id()
        Workspace.create(tmp_path / "cases" / hidden_id, "Restricted exhibit", case_id=hidden_id)
        case = Case.objects.create(id=case_id, title="Shared exhibit")
        Case.objects.create(id=hidden_id, title="Restricted exhibit")

        sessions = {}
        entries = ("owner", "editor-a", "editor-b", "viewer-a")
        accounts = get_user_model()
        for username, role in zip(entries, ("owner", "editor", "editor", "viewer")):
            password = secrets.token_urlsafe(21)
            account = accounts.objects.create_user(username=username, password=password)
            Membership.objects.create(case=case, user=account, role=role)
            sessions[username] = password

        exhibit = workspace.add("exhibit.txt", b"timeline entered")
        initial = save_note(workspace, "Initial note", "owner",
                            anchors=[{"kind": "artifact", "id": exhibit["id"]}])
        first_reviewer = tmp_path / "review"
        original_package = tmp_path / "review-bag"
        exchange.pack(workspace, original_package, include_files=True)
        exchange.unpack(original_package, first_reviewer)
        review = Workspace(first_reviewer)

        with api.sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch()
            except api.Error as exc:
                if "Executable doesn't exist" in str(exc):
                    pytest.skip("Playwright Chromium is not installed")
                raise
            with closing(browser):
                active = {}
                case_url = origin + f"/case/{case_id}/"
                for user, password in sessions.items():
                    context = browser.new_context(ignore_https_errors=True)
                    page = context.new_page()
                    page.set_default_timeout(12000)
                    establish(page, origin, user, password)
                    page.goto(case_url, wait_until="domcontentloaded")
                    api.expect(page.locator("#connection")).to_have_text("Live · connected")
                    page.get_by_role("button", name="Notes", exact=True).click()
                    api.expect(page.locator("#note-list")).to_contain_text("Initial note")
                    active[user] = (context, page)

                owner, owner_page = active["owner"]
                invite = post(owner, origin, case_url + "api/team/invite", {"role": "viewer"})
                assert invite.status == 201
                invite_url = invite.json()["url"]
                other_viewer = browser.new_context(ignore_https_errors=True)
                incoming = other_viewer.new_page()
                incoming.goto(invite_url)
                incoming.get_by_label("Username", exact=True).fill("viewer-b")
                incoming.get_by_label("Password", exact=True).fill(secrets.token_urlsafe(21))
                incoming.get_by_role("button", name="Accept invitation").click()
                incoming.wait_for_url(case_url)
                api.expect(incoming.locator("#connection")).to_have_text("Live · connected")
                assert owner.request.get(invite_url).status == 404
                assert other_viewer.request.get(origin + f"/case/{hidden_id}/api/state").status == 404
                assert post(other_viewer, origin, case_url + "api/notes", {"body": "Denied"}).status == 403

                editor_a, page_a = active["editor-a"]
                _, page_b = active["editor-b"]
                for page, body in ((page_a, "First editor saved"), (page_b, "Second editor pending")):
                    page.get_by_role("button", name="Edit", exact=True).click()
                    page.get_by_role("textbox", name="Note text").fill(body)
                page_a.get_by_role("button", name="Save note").click()
                api.expect(page_b.locator("#note-list")).to_contain_text("First editor saved")
                page_b.get_by_role("button", name="Save note").click()
                api.expect(page_b.locator("#status")).to_contain_text("Your draft is still here")
                api.expect(page_b.get_by_role("textbox", name="Note text")).to_have_value("Second editor pending")
                page_b.get_by_role("button", name="Review 1 current revision").click()
                page_b.get_by_role("textbox", name="Note text").fill("Merged editor decision")
                page_b.get_by_role("button", name="Save note").click()
                api.expect(owner_page.locator("#note-list")).to_contain_text("Merged editor decision")

                save_note(review, "Offline reviewer decision", "reviewer",
                          note_id=initial["note_id"], bases=[initial["id"]])
                reply = tmp_path / "review-reply"
                exchange.pack(review, reply)
                assert exchange.merge(workspace, reply, "owner")["inserted"] == 1
                assert exchange.merge(workspace, reply, "owner")["inserted"] == 0
                api.expect(owner_page.locator("#note-list")).to_contain_text("2 concurrent revisions")
                api.expect(owner_page.locator("#note-list")).to_contain_text("Offline reviewer decision")

                viewer, viewer_page = active["viewer-a"]
                delays = []
                payload = {"anchors": [{"kind": "artifact", "id": exhibit["id"]}]}
                for index in range(10):
                    text = f"Committed update {index:02d}"
                    started = time.perf_counter()
                    response = post(editor_a, origin, case_url + "api/notes", dict(payload, body=text),
                                    {"Idempotency-Key": new_id()})
                    assert response.status == 201
                    api.expect(viewer_page.locator("#note-list")).to_contain_text(text, timeout=5000)
                    delays.append(time.perf_counter() - started)
                p95 = statistics.quantiles(delays, n=20, method="inclusive")[18]
                print(f"Five HTTPS sessions on localhost, notes update p95: {p95:.3f} s ({len(delays)} messages)")
                assert p95 < 2

                viewer.set_offline(True)
                key = new_id()
                queued = dict(payload, body="Visible after reconnect")
                first = post(editor_a, origin, case_url + "api/notes", queued, {"Idempotency-Key": key})
                repeated = post(editor_a, origin, case_url + "api/notes", queued, {"Idempotency-Key": key})
                assert first.status == 201 and repeated.json() == first.json()
                viewer.set_offline(False)
                api.expect(viewer_page.locator("#note-list")).to_contain_text(queued["body"], timeout=12000)
                assert sum(note["body"] == queued["body"] for note in workspace.snapshot()["notes"]) == 1
                assert post(owner, origin, case_url + "api/team/revoke", {"user": "viewer-b"}).json()["removed"]
                api.expect(incoming.locator("#connection")).to_have_text("Live · access ended", timeout=5000)
                assert other_viewer.request.get(case_url + "api/state").status == 404


def test_public_team_cli_initializes_an_account_and_round_trips_a_package(tmp_path):
    pytest.importorskip("django")
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parents[2]
    host = tmp_path / "host"

    def team(*arguments, supplied=None):
        command = [sys.executable, "-B", "-m", "ctf_toolkit", "team", "--dir", str(host)]
        result = subprocess.run(command + list(map(str, arguments)), cwd=repo, input=supplied,
                                capture_output=True, timeout=45)
        assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
        return result.stdout

    phrase = secrets.token_urlsafe(24)
    assert b"Team host initialized" in team("init", "--admin", "workbench-lead",
                                              supplied=(phrase + "\n" + phrase + "\n").encode())
    work = Workspace.create(tmp_path / "original", "CLI review")
    work.add("manifest.txt", b"independent evidence bytes")
    exchange.pack(work, tmp_path / "outbound", include_files=True)
    assert b"Registered team case" in team("import", tmp_path / "outbound", "--owner", "workbench-lead")
    assert b"Wrote a verified package" in team("pack", work.info()["case_id"],
                                               "--out", tmp_path / "returned", "--with-files")
    assert exchange.check_pack(tmp_path / "returned")["artifacts"] == work.manifest()["artifacts"]
