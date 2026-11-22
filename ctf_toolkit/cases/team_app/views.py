"""Authenticated browser entry points and the team's committed event stream."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import sqlite3
from datetime import timedelta
from html import escape

from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import SESSION_KEY, HASH_SESSION_KEY, authenticate, get_user_model, login, logout
from django.contrib.auth.password_validation import validate_password
from django.contrib.sessions.backends.db import SessionStore
from django.core.cache import cache
from django.core.exceptions import RequestDataTooBig, ValidationError
from django.db import DatabaseError, IntegrityError, transaction
from django.http import HttpResponse, StreamingHttpResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect
from django.urls import path
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from django.views.decorators.http import require_http_methods

from ..local_web import CONTENT_SECURITY
from ..store import ID, Workspace, as_json, new_id
from ..web_api import MAX_JSON, MAX_UPLOAD, Response, dispatch, get_asset
from .models import Case, Invitation, Membership


def _secure(response):
    response["Cache-Control"] = "no-store"
    response["Content-Security-Policy"] = CONTENT_SECURITY
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _form(request, endpoint: str, fields: str, label: str) -> str:
    return (
        f'<form method="post" action="{escape(endpoint)}">'
        f'<input type="hidden" name="csrfmiddlewaretoken" value="{escape(get_token(request))}">'
        f'{fields}<button class="button primary" type="submit">{escape(label)}</button></form>'
    )


def _page(title: str, body: str, status: int = 200):
    return _secure(HttpResponse(
        '<!doctype html><html lang="en"><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>{escape(title)} · CTF Toolkit</title><link rel="stylesheet" href="/assets/style.css">'
        f'<body class="team-gate"><main><a class="wordmark" href="/">CTF Toolkit</a>'
        f'<h1>{escape(title)}</h1>{body}</main></body></html>', status=status,
    ))


def _credential_form(request, endpoint: str, label: str, *, create: bool = False) -> str:
    password_type = "new-password" if create else "current-password"
    fields = (
        '<label>Username <input required name="username" maxlength="150" autocomplete="username"></label>'
        f'<label>Password <input required name="password" type="password" autocomplete="{password_type}"></label>'
    )
    return _form(request, endpoint, fields, label)


def _rate_key(request, username: str) -> str:
    origin = request.META.get("REMOTE_ADDR", "unknown")
    return "auth-" + hashlib.sha256(f"{origin}:{username.lower()}".encode()).hexdigest()


def _record_failure(key: str) -> None:
    cache.add(key, 0, timeout=900)
    try:
        cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=900)


@require_http_methods(["GET", "POST"])
def signin(request):
    if request.user.is_authenticated:
        return redirect("/")
    message = ""
    status = 200
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        key = _rate_key(request, username)
        if cache.get(key, 0) >= 8:
            return _page("Sign in", "<p>Too many attempts. Try again in 15 minutes.</p>", 429)
        user = authenticate(request, username=username, password=request.POST.get("password", ""))
        if user is not None:
            cache.delete(key)
            login(request, user)
            return redirect("/")
        _record_failure(key)
        message = '<p class="error-text" role="alert">Username or password was not accepted.</p>'
        status = 401
    return _page("Sign in", message + _credential_form(request, "/login/", "Sign in"), status)


@require_http_methods(["GET", "POST"])
def index(request):
    if not request.user.is_authenticated:
        return redirect("/login/")
    if request.method == "POST":
        if not request.user.is_superuser:
            return _page("Permission required", "<p>A host administrator creates team cases.</p>", 403)
        title = request.POST.get("title", "").strip()
        if not title or len(title) > 200:
            return _page("New case", "<p>Enter a case title of 1–200 characters.</p>", 400)
        case_id = new_id()
        Workspace.create(settings.CTFTK_TEAM_DIR / "cases" / case_id, title, case_id=case_id)
        with transaction.atomic():
            case = Case.objects.create(id=case_id, title=title)
            Membership.objects.create(case=case, user=request.user, role="owner")
        return redirect(f"/case/{case.id}/")
    cases = Case.objects.order_by("title")
    if not request.user.is_superuser:
        cases = cases.filter(membership__user=request.user)
    rows = "".join(f'<li><a href="/case/{row.id}/">{escape(row.title)}</a></li>' for row in cases)
    listing = f'<ul class="case-list">{rows}</ul>' if rows else "<p>No case invitations have been accepted.</p>"
    create = _form(request, "/", '<label>Case title <input required name="title" maxlength="200"></label>',
                   "Create case") if request.user.is_superuser else ""
    return _page("Team cases", listing + create + _form(request, "/logout/", "", "Sign out"))


@require_http_methods(["POST"])
def signout(request):
    logout(request)
    return redirect("/login/")


def _role(case_id: str, user) -> str | None:
    if not ID.fullmatch(case_id) or not user.is_authenticated or not user.is_active:
        return None
    if user.is_superuser:
        return "owner" if Case.objects.filter(pk=case_id).exists() else None
    return Membership.objects.filter(case_id=case_id, user_id=user.pk).values_list("role", flat=True).first()


def _workspace(case_id: str) -> Workspace:
    return Workspace(settings.CTFTK_TEAM_DIR / "cases" / case_id)


@require_http_methods(["GET"])
def asset(request, name):
    try:
        data, content_type = get_asset(name)
    except LookupError:
        return HttpResponse(status=404)
    return _secure(HttpResponse(data, content_type=content_type))


@require_http_methods(["GET"])
def workbench(request, case_id):
    if not request.user.is_authenticated:
        return redirect("/login/")
    if _role(case_id, request.user) is None:
        return _page("Case unavailable", "<p>Your account cannot open this case.</p>", 404)
    get_token(request)
    page, content_type = get_asset("index.html")
    page = page.replace(b'data-mode="local"', b'data-mode="team"')
    return _secure(HttpResponse(page, content_type=content_type))


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _json(result: Response):
    response = HttpResponse(result.body, status=result.status, content_type=result.content_type)
    if result.attachment:
        response["Content-Disposition"] = f'attachment; filename="{result.attachment}"'
    return _secure(response)


def _team_operation(request, route: str, case_id: str, role: str, raw: bytes) -> Response:
    if role != "owner":
        return Response({"error": "Case membership is managed by the owner"}, 403)
    if request.method == "GET" and route == "team/members":
        members = Membership.objects.filter(case_id=case_id).order_by("user__username")
        return Response([{"user": item.user.username, "role": item.role} for item in members.select_related("user")])
    if request.method != "POST":
        return Response({"error": "Method is unsupported"}, 405)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    if route == "team/invite" and data.get("role") in {"editor", "viewer"}:
        token = secrets.token_urlsafe(32)
        Invitation.objects.create(case_id=case_id, digest=_digest(token), role=data["role"],
                                  expires_at=timezone.now() + timedelta(hours=24))
        return Response({"url": settings.CTFTK_ORIGIN + f"/join/{token}/", "expires_in_hours": 24}, 201)
    if route == "team/revoke" and isinstance(data.get("user"), str):
        removed, _ = Membership.objects.filter(case_id=case_id, user__username=data["user"]).exclude(
            role="owner"
        ).delete()
        return Response({"removed": bool(removed)})
    return Response({"error": "Choose a valid team operation and role"}, 400)


@require_http_methods(["GET", "POST"])
def case_api(request, case_id, route):
    role = _role(case_id, request.user)
    if role is None:
        return _json(Response({"error": "Case unavailable"}, 404))
    limit = MAX_UPLOAD if route == "import" else MAX_JSON
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
        if length < 0:
            raise ValueError("Invalid request length")
        if length > limit:
            return _json(Response({"error": "Request exceeds the allowed size"}, 413))
        raw = request.body if request.method == "POST" else b""
        if len(raw) > limit:
            return _json(Response({"error": "Request exceeds the allowed size"}, 413))
        if route.startswith("team/"):
            return _json(_team_operation(request, route, case_id, role, raw))
        return _json(dispatch(_workspace(case_id), request.method, route, request.GET, request.headers, raw,
                              role=role, author=request.user.get_username()))
    except RequestDataTooBig:
        return _json(Response({"error": "Request exceeds the allowed size"}, 413))
    except (ValueError, TypeError, RecursionError) as exc:
        return _json(Response({"error": str(exc)}, 400))
    except (DatabaseError, OSError):
        return _json(Response({"error": "Case storage is temporarily unavailable"}, 503))


@require_http_methods(["GET", "POST"])
def join(request, token):
    if len(token) != 43 or not all(char.isascii() and (char.isalnum() or char in "-_") for char in token):
        return _page("Invitation unavailable", "<p>This invitation is invalid or has expired.</p>", 404)
    invite = Invitation.objects.filter(digest=_digest(token), used_at__isnull=True,
                                       expires_at__gt=timezone.now()).select_related("case").first()
    if invite is None:
        return _page("Invitation unavailable", "<p>This invitation is invalid or has expired.</p>", 404)
    endpoint = f"/join/{token}/"
    auth = request.user.is_authenticated
    form = (_form(request, endpoint, "", "Accept invitation") if auth
            else _credential_form(request, endpoint, "Accept invitation", create=True))
    prompt = f"<p>Open <strong>{escape(invite.case.title)}</strong> as {invite.role}.</p>"
    if request.method == "GET":
        return _page("Case invitation", prompt + form)
    user = request.user if auth else None
    raw_password = None
    if not auth:
        username = request.POST.get("username", "").strip()
        raw_password = request.POST.get("password", "")
        key = _rate_key(request, username)
        if cache.get(key, 0) >= 8:
            return _page("Case invitation", "<p>Too many attempts. Try again in 15 minutes.</p>", 429)
        accounts = get_user_model()
        try:
            if not username or len(username) > 150:
                raise ValidationError("Enter a username of 1–150 characters.")
            accounts._meta.get_field("username").run_validators(username)
            existing = accounts.objects.filter(username=username).exists()
            user = authenticate(request, username=username, password=raw_password) if existing else accounts(username=username)
            if user is None:
                _record_failure(key)
                raise ValidationError("Username or password was not accepted.")
            if not existing:
                validate_password(raw_password, user)
        except ValidationError as exc:
            return _page("Case invitation", prompt + f'<p class="error-text">{escape(" ".join(exc.messages))}</p>' + form, 400)
        cache.delete(key)
    try:
        with transaction.atomic():
            consumed = Invitation.objects.filter(pk=invite.pk, used_at__isnull=True,
                                                 expires_at__gt=timezone.now()).update(used_at=timezone.now())
            if not consumed:
                return _page("Invitation unavailable", "<p>This invitation has already been used.</p>", 409)
            if user.pk is None:
                user.set_password(raw_password)
                user.save()
            Membership.objects.get_or_create(case_id=invite.case_id, user=user,
                                             defaults={"role": invite.role})
    except IntegrityError:
        return _page("Case invitation", prompt + '<p class="error-text">Account changed. Try again.</p>' + form, 409)
    except DatabaseError:
        return _page("Case invitation", prompt + '<p class="error-text">Storage is busy. Retry shortly.</p>' + form, 503)
    if not auth:
        login(request, user)
    return redirect(f"/case/{invite.case_id}/")


def _poll(case_id: str, session_key: str, user_id: int, cursor: int) -> list[dict] | None:
    session = SessionStore(session_key=session_key)
    user = get_user_model().objects.filter(pk=user_id).first()
    if user is None or str(session.get(SESSION_KEY)) != str(user_id):
        return None
    if not constant_time_compare(session.get(HASH_SESSION_KEY, ""), user.get_session_auth_hash()):
        return None
    if _role(case_id, user) is None:
        return None
    return _workspace(case_id).changes(cursor)


async def updates(request, case_id):
    if request.method != "GET":
        return _json(Response({"error": "Method is unsupported"}, 405))
    user = await request.auser()
    if await sync_to_async(_role)(case_id, user) is None:
        return _json(Response({"error": "Case unavailable"}, 404))
    try:
        cursor = int(request.headers.get("Last-Event-ID") or request.GET.get("after", "0"))
        if not 0 <= cursor <= 2**63 - 1:
            raise ValueError
    except ValueError:
        return _json(Response({"error": "Invalid change cursor"}, 400))
    session_key = request.session.session_key

    async def stream():
        nonlocal cursor
        yield b": connected\n\n"
        for tick in range(600):
            try:
                batch = await sync_to_async(_poll)(case_id, session_key, user.pk, cursor)
            except (DatabaseError, sqlite3.Error, OSError):
                break
            if batch is None:
                yield b"event: unavailable\ndata: {}\n\n"
                return
            for item in batch:
                cursor = item["seq"]
                yield f"id: {cursor}\ndata: {as_json(item)}\n\n".encode("ascii")
            if not batch and tick % 30 == 0:
                yield b": keepalive\n\n"
            await asyncio.sleep(0.35)

    response = StreamingHttpResponse(stream(), content_type="text/event-stream")
    response["X-Accel-Buffering"] = "no"
    return _secure(response)


urlpatterns = [
    path("", index), path("login/", signin), path("logout/", signout),
    path("assets/<str:name>", asset), path("join/<str:token>/", join),
    path("case/<str:case_id>/", workbench),
    path("case/<str:case_id>/api/updates", updates),
    path("case/<str:case_id>/api/<path:route>", case_api),
]
