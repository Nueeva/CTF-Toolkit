"""Evidence annotations with explicit ancestry and concurrent revision heads."""

from __future__ import annotations

import sqlite3
from hashlib import sha256

from .store import ID, Workspace, as_json, new_id, now, parse_row, revisions


class NoteConflict(ValueError):
    def __init__(self, current: list[dict]):
        self.current = current
        super().__init__("The note changed. Review the current revisions before saving again.")


def validate_anchors(conn: sqlite3.Connection, anchors: list[dict]) -> None:
    if not isinstance(anchors, list) or not 1 <= len(anchors) <= 8:
        raise ValueError("A note must reference 1–8 evidence locations")
    for anchor in anchors:
        if not isinstance(anchor, dict):
            raise ValueError("Invalid evidence location")
        kind = anchor.get("kind")
        identifier = anchor.get("id")
        if not isinstance(identifier, str) or not ID.fullmatch(identifier):
            raise ValueError("Invalid evidence location identifier")
        if kind == "event":
            if not conn.execute("SELECT 1 FROM timeline WHERE id=?", (identifier,)).fetchone():
                raise ValueError("Timeline event is outside this case")
        elif kind in {"artifact", "bytes"}:
            row = conn.execute("SELECT size FROM artifacts WHERE id=?", (identifier,)).fetchone()
            if not row:
                raise ValueError("Artifact is outside this case")
            if kind == "bytes":
                start, stop = anchor.get("start"), anchor.get("stop")
                if type(start) is not int or type(stop) is not int or not 0 <= start < stop <= row["size"]:
                    raise ValueError("Bookmark range is outside its artifact")
        else:
            raise ValueError("Unknown evidence location")


def note_body_valid(body: object, author: object) -> bool:
    return (isinstance(body, str) and bool(body.strip()) and len(body) <= 8192
            and isinstance(author, str) and bool(author.strip()) and len(author) <= 150)


def save_note(
    workspace: Workspace, body: str, author: str, *, anchors: list[dict] | None = None,
    note_id: str | None = None, bases: list[str] | None = None, request_id: str | None = None,
) -> dict:
    if not note_body_valid(body, author):
        raise ValueError("A note needs an author and 1–8192 characters of text")
    if bases is not None and (
        not isinstance(bases, list) or any(not isinstance(base, str) or not ID.fullmatch(base) for base in bases)
        or len(set(bases)) != len(bases)
    ):
        raise ValueError("Invalid note revisions")
    bases = sorted(bases or [])
    revision_id = new_id()
    fingerprint = None
    if request_id is not None:
        if not ID.fullmatch(request_id):
            raise ValueError("Invalid idempotency key")
        fingerprint = sha256(as_json([author, note_id, anchors, bases, body]).encode("ascii")).hexdigest()
    with workspace.transaction(write=True) as conn:
        if request_id:
            prior = conn.execute("SELECT * FROM note_requests WHERE key=?", (request_id,)).fetchone()
            if prior:
                if prior["fingerprint"] != fingerprint:
                    raise ValueError("Idempotency key was already used for a different edit")
                recorded = conn.execute("SELECT * FROM revisions WHERE id=?", (prior["revision_id"],)).fetchone()
                return dict(parse_row(recorded, "anchor"), bases=bases)
        if note_id is None:
            if bases:
                raise ValueError("A new note does not have a base revision")
            note_id = new_id()
        else:
            if not isinstance(note_id, str) or not ID.fullmatch(note_id):
                raise ValueError("Invalid note identifier")
            current = [item for item in revisions(conn) if item["note_id"] == note_id]
            if not current:
                raise LookupError("Note does not exist")
            if bases != sorted(row["id"] for row in current):
                raise NoteConflict(current)
            if anchors is None:
                anchors = current[0]["anchor"]
        validate_anchors(conn, anchors)
        created = now()
        conn.execute("INSERT INTO revisions VALUES (?, ?, ?, ?, ?, ?, NULL)",
                     (revision_id, note_id, author, as_json(anchors), body, created))
        conn.executemany("INSERT INTO revision_parents VALUES (?, ?)",
                         ((revision_id, base) for base in bases))
        if request_id:
            conn.execute("INSERT INTO note_requests VALUES (?, ?, ?)", (request_id, fingerprint, revision_id))
        workspace.change(conn, "note", note_id)
    return {"id": revision_id, "note_id": note_id, "author": author, "anchor": anchors,
            "body": body, "created_at": created, "imported_by": None, "bases": bases}
