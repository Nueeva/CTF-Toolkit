"""The evidence API shared by the loopback Workbench and private team host."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote

from . import operations
from .caesar import rank_caesar
from .exchange import report_markdown
from .notes import NoteConflict, save_note
from .store import Workspace, as_json, parse_row
from .timeline import index_timeline, timeline

MAX_UPLOAD = 8 * 1024 * 1024
MAX_JSON = 64 * 1024


@dataclass(frozen=True)
class Response:
    data: object
    status: int = 200
    content_type: str = "application/json"
    attachment: str | None = None

    @property
    def body(self) -> bytes:
        return self.data if isinstance(self.data, bytes) else as_json(self.data).encode("ascii")


def get_asset(name: str) -> tuple[bytes, str]:
    from importlib.resources import files
    content_types = {"index.html": "text/html", "style.css": "text/css", "app.js": "text/javascript"}
    if name not in content_types:
        raise LookupError("Unknown Workbench asset")
    return files("ctf_toolkit.cases").joinpath("assets", name).read_bytes(), content_types[name] + "; charset=utf-8"


def note_etag(bases: list[str]) -> str:
    return '"' + ".".join(sorted(bases)) + '"'


def _read_json(raw: bytes) -> dict:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def _get(workspace: Workspace, route: list[str], query, role: str) -> Response:
    def number(field: str, default: int | None = None) -> int | None:
        return int(query[field]) if query.get(field) not in (None, "") else default

    if route == ["state"]:
        return Response({**workspace.snapshot(), "role": role})
    if len(route) >= 2 and route[0] == "artifact":
        artifact = route[1]
        if len(route) == 2:
            return Response(operations.inspect_saved(workspace, artifact, number("offset", 0)))
        if route[2:] == ["source"]:
            return Response(operations.source_region(workspace, artifact, number("start", 0), number("stop", 1)))
        if route[2:] == ["download"]:
            if role != "owner":
                return Response({"error": "Artifact downloads require the case owner"}, 403)
            payload = workspace.blob(workspace.artifact(artifact))
            return Response(payload, content_type="application/octet-stream", attachment="artifact.bin")
    if route == ["timeline"]:
        offset = number("offset", 0)
        if offset < 0:
            raise ValueError("Timeline offset must be nonnegative")
        return Response(timeline(workspace, query.get("artifact") or None,
                                 number("start"), number("stop"), 200, offset))
    if len(route) == 2 and route[0] == "event":
        with workspace.transaction() as conn:
            row = conn.execute("SELECT * FROM timeline WHERE id=?", (route[1],)).fetchone()
            if row is None:
                raise LookupError("Event does not exist")
            return Response(parse_row(row, "event"))
    if route == ["compare"]:
        return Response(operations.compare(workspace, query["left"], query["right"],
                                           number("offset_a", 0), number("offset_b", 0)))
    if route == ["verify"]:
        return Response(operations.verify(workspace, replay=query.get("replay") == "true"))
    if route == ["caesar"]:
        raw = workspace.blob(workspace.artifact(query["artifact"]))
        return Response(rank_caesar(raw.decode("utf-8"), query["lang"]))
    if route in (["export", "report"], ["export", "manifest"]):
        document = workspace.manifest()
        if route[-1] == "report":
            return Response(report_markdown(document).encode(), content_type="text/markdown; charset=utf-8",
                            attachment="report.md")
        return Response(document, attachment="case.json")
    raise LookupError("Unknown evidence endpoint")


def _post(workspace: Workspace, route: list[str], headers, body: bytes, author: str, role: str) -> Response:
    if role not in {"owner", "editor"}:
        return Response({"error": "This case is read-only for your account"}, 403)
    if route == ["import"]:
        if len(body) > MAX_UPLOAD:
            return Response({"error": "Browser uploads are limited to 8 MiB"}, 413)
        if headers.get("Content-Type") != "application/octet-stream":
            return Response({"error": "Select a file to upload its bytes"}, 415)
        supplied = unquote(headers.get("X-Artifact-Name", ""))
        label = PurePosixPath(supplied.replace("\\", "/")).name
        if not label:
            raise ValueError("The upload needs a file name")
        return Response(workspace.add(label, body), 201)
    if len(body) > MAX_JSON:
        return Response({"error": "The request is too large"}, 413)
    if headers.get("Content-Type", "").split(";")[0] != "application/json":
        return Response({"error": "Expected application/json"}, 415)
    data = _read_json(body)
    if route == ["analyze"]:
        return Response(operations.analyze(workspace, data["artifact"]))
    if route == ["recipe"]:
        return Response(operations.transform(workspace, data["artifact"], data["recipe"],
                                             preview=data.get("preview") is True))
    if route == ["timeline"]:
        return Response(index_timeline(workspace, data["artifact"], data["profile"], data.get("timezone")))
    if route == ["notes"]:
        note = data.get("note_id")
        bases = data.get("bases")
        if note is not None:
            if not isinstance(bases, list) or any(not isinstance(base, str) for base in bases):
                raise ValueError("Expected base revision identifiers")
            if headers.get("If-Match") != note_etag(bases):
                return Response({"error": "A matching If-Match revision is required"}, 428)
        return Response(save_note(workspace, data["body"], author, anchors=data.get("anchors"),
                                  note_id=note, bases=bases, request_id=headers.get("Idempotency-Key")), 201)
    raise LookupError("Unknown evidence endpoint")


def dispatch(workspace: Workspace, method: str, path: str, query, headers, body: bytes = b"",
             *, role: str = "owner", author: str = "local") -> Response:
    route = path.strip("/").split("/")
    try:
        if method == "GET":
            return _get(workspace, route, query, role)
        if method == "POST":
            return _post(workspace, route, headers, body, author, role)
        return Response({"error": "Method is unsupported"}, 405)
    except NoteConflict as exc:
        return Response({"error": str(exc), "current": exc.current}, 412)
    except KeyError as exc:
        return Response({"error": f"Missing field {exc}"}, 400)
    except LookupError as exc:
        return Response({"error": str(exc)}, 404)
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        return Response({"error": str(exc)}, 400)
    except (OSError, sqlite3.Error):
        return Response({"error": "Could not access case storage. Check the workspace and try again."}, 503)
