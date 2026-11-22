"""Provision and serve a private team host over HTTPS."""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import urlsplit

from . import exchange
from .store import ID, Workspace
from .web_api import MAX_UPLOAD


def configure(directory: Path, origin: str, secret: str) -> None:
    import django
    from django.conf import settings

    address = urlsplit(origin)
    if (address.scheme != "https" or not address.hostname or address.username or address.password
            or address.path not in ("", "/") or address.query or address.fragment):
        raise ValueError("Team origin must be an HTTPS origin without a path")
    hostname = f"[{address.hostname}]" if ":" in address.hostname else address.hostname
    if settings.configured:
        if settings.CTFTK_TEAM_DIR != directory.resolve():
            raise ValueError("A team host is already configured in this process")
        return
    settings.configure(
        SECRET_KEY=secret,
        DEBUG=False,
        ALLOWED_HOSTS=[hostname],
        CSRF_TRUSTED_ORIGINS=[origin.rstrip("/")],
        ROOT_URLCONF="ctf_toolkit.cases.team_app.views",
        INSTALLED_APPS=[
            "django.contrib.contenttypes", "django.contrib.auth", "django.contrib.sessions",
            "ctf_toolkit.cases.team_app",
        ],
        MIDDLEWARE=[
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django.middleware.clickjacking.XFrameOptionsMiddleware",
        ],
        DATABASES={"default": {
            "ENGINE": "django.db.backends.sqlite3", "NAME": str(directory / "team.sqlite3"),
            "OPTIONS": {"timeout": 10},
        }},
        AUTH_PASSWORD_VALIDATORS=[
            {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
            {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
            {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
            {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
        ],
        CSRF_COOKIE_SECURE=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_AGE=8 * 60 * 60,
        SECURE_SSL_REDIRECT=True,
        SECURE_CONTENT_TYPE_NOSNIFF=True,
        SECURE_REFERRER_POLICY="same-origin",
        X_FRAME_OPTIONS="DENY",
        DATA_UPLOAD_MAX_MEMORY_SIZE=MAX_UPLOAD,
        USE_TZ=True,
        TIME_ZONE="UTC",
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        CTFTK_TEAM_DIR=directory.resolve(),
        CTFTK_ORIGIN=origin.rstrip("/"),
    )
    django.setup()


def _secret(directory: Path, create: bool) -> str:
    path = directory / "host-key"
    if create and not path.exists():
        directory.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(secrets.token_urlsafe(64))
    if not path.is_file():
        raise ValueError("Initialize the team host first with team init")
    value = path.read_text(encoding="ascii").strip()
    if len(value) < 64:
        raise ValueError("Team host key is invalid")
    return value


def _known_case(directory: Path, case_id: str) -> Workspace:
    from .team_app.models import Case
    if not ID.fullmatch(case_id) or not Case.objects.filter(id=case_id).exists():
        raise ValueError("Case is not registered on this host")
    return Workspace(directory / "cases" / case_id)


def _ensure_admin(accounts, username: str) -> None:
    from django.contrib.auth.password_validation import validate_password
    from django.core.exceptions import ValidationError

    existing = accounts.objects.filter(username=username).first()
    if existing is not None:
        if not existing.is_active or not existing.is_superuser:
            raise ValueError("The requested username belongs to a non-administrative or inactive account")
        return
    candidate = accounts(username=username)
    try:
        accounts._meta.get_field("username").clean(username, candidate)
        if sys.stdin.isatty():
            entered = getpass.getpass("New administrator password: ")
            confirmation = getpass.getpass("Repeat administrator password: ")
        else:
            entered = sys.stdin.readline().rstrip("\r\n")
            confirmation = sys.stdin.readline().rstrip("\r\n")
            if not entered or not confirmation:
                raise EOFError
        if entered != confirmation:
            raise ValueError("Administrator passwords did not match")
        validate_password(entered, candidate)
    except EOFError as exc:
        raise ValueError("Initialization needs an administrator password at the prompt") from exc
    except ValidationError as exc:
        raise ValueError(" ".join(exc.messages)) from exc
    accounts.objects.create_superuser(username=username, email="", password=entered)


def execute(args: argparse.Namespace) -> int:
    try:
        from django.contrib.auth import get_user_model
        from django.core.management import call_command
    except ImportError as exc:
        raise ValueError("Install ctf-toolkit[team] to use private team hosting") from exc

    directory = args.dir.resolve()
    secret = _secret(directory, args.action == "init")
    configure(directory, args.origin if args.action == "serve" else "https://127.0.0.1", secret)
    from .team_app.models import Case, Membership

    if args.action == "init":
        call_command("migrate", interactive=False, verbosity=0)
        _ensure_admin(get_user_model(), args.admin)
        print(f"Team host initialized in {directory}")
    elif args.action == "serve":
        if not 1 <= args.port <= 65535 or not args.cert.is_file() or not args.key.is_file():
            raise ValueError("Provide a port and readable TLS certificate and key")
        try:
            import uvicorn
        except ImportError as exc:
            raise ValueError("Install ctf-toolkit[team] to serve the case host") from exc
        from django.core.asgi import get_asgi_application
        call_command("migrate", interactive=False, verbosity=0)
        uvicorn.run(get_asgi_application(), host=args.host, port=args.port,
                    ssl_certfile=str(args.cert), ssl_keyfile=str(args.key), proxy_headers=False,
                    server_header=False, access_log=False, lifespan="off", timeout_graceful_shutdown=5)
    elif args.action == "import":
        from django.db import transaction

        user = get_user_model().objects.filter(username=args.owner, is_active=True).first()
        if user is None:
            raise ValueError("Case owner must be an active host account")
        manifest = exchange.check_pack(args.package)
        case_id = manifest["case"]["case_id"]
        target = directory / "cases" / case_id
        if target.exists():
            exchange.merge(Workspace(target), args.package, user.get_username())
        else:
            exchange.unpack(args.package, target, user.get_username())
        with transaction.atomic():
            case, created = Case.objects.get_or_create(id=case_id, defaults={"title": manifest["case"]["title"]})
            Membership.objects.update_or_create(case=case, user=user, defaults={"role": "owner"})
        print(f"{'Registered' if created else 'Updated'} team case {case_id}")
    elif args.action == "merge":
        actor = get_user_model().objects.filter(username=args.actor, is_active=True).first()
        if actor is None:
            raise ValueError("Merge actor must be an active host account")
        case = _known_case(directory, args.id)
        result = exchange.merge(case, args.package, actor.get_username())
        print(f"Imported {result['inserted']} records and {result['restored_objects']} evidence objects")
    elif args.action == "pack":
        case = _known_case(directory, args.id)
        exchange.pack(case, args.out, include_files=args.with_files)
        print(f"Wrote a verified package to {args.out}")
    else:
        raise ValueError("Unknown team operation")
    return 0
