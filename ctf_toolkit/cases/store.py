"""SQLite metadata and immutable, checksum-addressed evidence blobs."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .transforms import MAX_ARTIFACT_BYTES, sha256

SCHEMA_VERSION = 1
DB_FILE = "case.sqlite3"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
SCHEMA = """
CREATE TABLE metadata (case_id TEXT PRIMARY KEY, title TEXT NOT NULL);
CREATE TABLE runs (
    id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES artifacts(id),
    kind TEXT NOT NULL, status TEXT NOT NULL, engine TEXT NOT NULL,
    details TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE artifacts (
    id TEXT PRIMARY KEY, digest TEXT NOT NULL, size INTEGER NOT NULL CHECK(size >= 0),
    label TEXT NOT NULL, parent_id TEXT REFERENCES artifacts(id),
    operation TEXT NOT NULL, source TEXT NOT NULL,
    run_id TEXT REFERENCES runs(id), created_at TEXT NOT NULL
);
CREATE INDEX artifacts_parent ON artifacts(parent_id);
CREATE INDEX artifacts_run ON artifacts(run_id);
CREATE TABLE inspections (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id), run_id TEXT NOT NULL REFERENCES runs(id),
    report TEXT NOT NULL, PRIMARY KEY(artifact_id, run_id)
);
CREATE TABLE timeline (
    id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    seconds INTEGER, nanos INTEGER, event TEXT NOT NULL
);
CREATE INDEX timeline_order ON timeline(seconds, nanos, artifact_id, id);
CREATE TABLE revisions (
    id TEXT PRIMARY KEY, note_id TEXT NOT NULL, author TEXT NOT NULL,
    anchor TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL,
    imported_by TEXT
);
CREATE INDEX revisions_note ON revisions(note_id);
CREATE TABLE revision_parents (
    revision_id TEXT NOT NULL REFERENCES revisions(id),
    parent_id TEXT NOT NULL REFERENCES revisions(id),
    PRIMARY KEY(revision_id, parent_id)
);
CREATE INDEX revisions_parent ON revision_parents(parent_id);
CREATE TABLE note_requests (
    key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, revision_id TEXT NOT NULL REFERENCES revisions(id)
);
CREATE TABLE changes (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, object_id TEXT NOT NULL
);
"""


def new_id() -> str:
    return uuid.uuid4().hex


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def as_json(data: object) -> str:
    return json.dumps(data, ensure_ascii=True, sort_keys=True, allow_nan=False)


def parse_row(row: sqlite3.Row, *json_fields: str) -> dict:
    record = dict(row)
    for key in json_fields:
        record[key] = json.loads(record[key])
    return record


def read_file(path: Path, limit: int = MAX_ARTIFACT_BYTES) -> bytes:
    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")
    if path.stat().st_size > limit:
        raise ValueError(f"File exceeds the {limit} byte limit: {path.name}")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"File exceeds the {limit} byte limit: {path.name}")
    return data


class Workspace:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory).resolve()
        self.database = self.directory / DB_FILE
        if not self.database.is_file():
            raise ValueError(f"No case workspace in {self.directory}")
        self.objects = self.directory / "objects"

    @classmethod
    def create(
        cls, directory: str | Path, title: str | None = None, *, case_id: str | None = None
    ) -> Workspace:
        directory = Path(directory).resolve()
        case_id = case_id or new_id()
        title = title if title is not None else directory.name
        if not ID.fullmatch(case_id) or not title.strip() or len(title) > 200:
            raise ValueError("Case identifier or title is invalid")
        directory.mkdir(parents=True, exist_ok=True)
        database = directory / DB_FILE
        # Exclusive creation also prevents two concurrent init calls from overwriting a case.
        database.touch(exist_ok=False, mode=0o600)
        with closing(sqlite3.connect(database)) as connection:
            connection.executescript(SCHEMA)
            with connection:
                connection.execute("INSERT INTO metadata VALUES (?, ?)", (case_id, title))
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        return cls(directory)

    @contextmanager
    def transaction(self, *, write: bool = False):
        if not self.database.is_file():
            raise ValueError("Case database is missing")
        with closing(sqlite3.connect(self.database, timeout=10)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            if conn.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise ValueError("Case schema is unsupported by this version")
            with conn:
                conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield conn

    def info(self) -> dict:
        with self.transaction() as conn:
            return dict(conn.execute("SELECT * FROM metadata").fetchone())

    def blob_path(self, digest: str) -> Path:
        if not DIGEST.fullmatch(digest):
            raise ValueError("Invalid evidence digest")
        return self.objects / digest[:2] / digest

    def blob(self, artifact: dict) -> bytes:
        data = read_file(self.blob_path(artifact["digest"]))
        if len(data) != artifact["size"] or sha256(data) != artifact["digest"]:
            raise ValueError(f"Stored bytes failed verification: {artifact['id']}")
        return data

    def write_blob(self, data: bytes) -> str:
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ValueError("Evidence exceeds the artifact size limit")
        digest = sha256(data)
        target = self.blob_path(digest)
        if target.exists():
            self.blob({"id": digest, "digest": digest, "size": len(data)})
            return digest
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".incoming-", delete=False) as stream:
            staging = Path(stream.name)
        try:
            with staging.open("wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(staging, target)
        finally:
            staging.unlink(missing_ok=True)
        return digest

    @staticmethod
    def _artifact(conn: sqlite3.Connection, artifact_id: str) -> dict:
        row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
        if row is None:
            raise LookupError(f"Artifact does not exist: {artifact_id}")
        return parse_row(row, "source")

    def artifact(self, artifact_id: str) -> dict:
        with self.transaction() as conn:
            return self._artifact(conn, artifact_id)

    def insert_artifact(
        self, conn: sqlite3.Connection, data: bytes, label: str, *, operation: str = "import",
        parent_id: str | None = None, run_id: str | None = None, source: dict | None = None,
    ) -> dict:
        if not label.strip() or len(label) > 1024:
            raise ValueError("Artifact label must contain 1–1024 characters")
        artifact_id = new_id()
        conn.execute(
            "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (artifact_id, self.write_blob(data), len(data), label, parent_id, operation,
             as_json(source or {"kind": "file"}), run_id, now()),
        )
        return self._artifact(conn, artifact_id)

    @staticmethod
    def change(conn: sqlite3.Connection, kind: str, object_id: str) -> None:
        conn.execute("INSERT INTO changes(kind,object_id) VALUES (?, ?)", (kind, object_id))

    def add(self, label: str, data: bytes) -> dict:
        with self.transaction(write=True) as conn:
            artifact = self.insert_artifact(conn, data, label)
            self.change(conn, "artifact", artifact["id"])
        return artifact

    def changes(self, after: int) -> list[dict]:
        with self.transaction() as conn:
            rows = conn.execute("SELECT * FROM changes WHERE seq > ? ORDER BY seq LIMIT 100", (after,))
            return [dict(row) for row in rows]

    def snapshot(self) -> dict:
        with self.transaction() as conn:
            return {
                "case": dict(conn.execute("SELECT * FROM metadata").fetchone()),
                "seq": conn.execute("SELECT coalesce(max(seq), 0) FROM changes").fetchone()[0],
                "artifacts": [parse_row(row, "source") for row in conn.execute("SELECT * FROM artifacts ORDER BY rowid")],
                "runs": [parse_row(row, "details") for row in conn.execute("SELECT * FROM runs ORDER BY rowid")],
                "notes": revisions(conn),
            }

    def manifest(self) -> dict:
        """Produce an internally consistent, portable view of persisted records."""
        with self.transaction() as conn:
            return {
                "schema_version": SCHEMA_VERSION,
                "case": dict(conn.execute("SELECT * FROM metadata").fetchone()),
                "artifacts": [parse_row(row, "source") for row in conn.execute("SELECT * FROM artifacts ORDER BY rowid")],
                "runs": [parse_row(row, "details") for row in conn.execute("SELECT * FROM runs ORDER BY rowid")],
                "inspections": [parse_row(row, "report") for row in conn.execute("SELECT * FROM inspections ORDER BY rowid")],
                "timeline": [parse_row(row, "event") for row in conn.execute("SELECT * FROM timeline ORDER BY rowid")],
                "revisions": revisions(conn, include_history=True),
            }


def revisions(conn: sqlite3.Connection, *, include_history: bool = False) -> list[dict]:
    query = "SELECT * FROM revisions"
    if not include_history:
        query += " WHERE NOT EXISTS (SELECT 1 FROM revision_parents WHERE parent_id = revisions.id)"
    rows = conn.execute(query + " ORDER BY rowid")
    parents: dict[str, list[str]] = {}
    for parent in conn.execute("SELECT * FROM revision_parents ORDER BY parent_id"):
        parents.setdefault(parent["revision_id"], []).append(parent["parent_id"])
    return [dict(parse_row(row, "anchor"), bases=parents.get(row["id"], [])) for row in rows]
