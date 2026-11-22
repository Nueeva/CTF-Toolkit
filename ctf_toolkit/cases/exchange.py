"""Portable metadata exports and offline case handoffs."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .notes import note_body_valid, validate_anchors
from .store import DIGEST, ID, SCHEMA_VERSION, Workspace, as_json, parse_row, read_file
from .timeline import timesketch
from .transforms import MAX_ARTIFACT_BYTES

_LABEL = "BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n"
_ALGORITHMS = ("sha256", "sha512")
_MAX_MANIFEST = 64 * 1024 * 1024
_RECORDS = (
    ("artifacts", ("id", "digest", "size", "label", "parent_id", "operation", "source", "run_id", "created_at"), ("source",), ("id",)),
    ("runs", ("id", "source_id", "kind", "status", "engine", "details", "created_at"), ("details",), ("id",)),
    ("inspections", ("artifact_id", "run_id", "report"), ("report",), ("artifact_id", "run_id")),
    ("timeline", ("id", "artifact_id", "seconds", "nanos", "event"), ("event",), ("id",)),
    ("revisions", ("id", "note_id", "author", "anchor", "body", "created_at", "imported_by"), ("anchor",), ("id",)),
)


@contextmanager
def _publish_folder(destination: str | Path):
    target = Path(destination).absolute()
    if target.exists() or target.is_symlink():
        raise ValueError(f"Destination already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".ctftk-transfer-") as staging:
        payload = Path(staging) / "payload"
        payload.mkdir()
        yield payload
        if target.exists() or target.is_symlink():
            raise ValueError(f"Destination already exists: {target}")
        payload.rename(target)


def _markdown(text: object) -> str:
    escaped = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\\x60*_\[\]#|!])", r"\\\1", escaped).replace("\r", " ").replace("\n", " ")


def report_markdown(manifest: dict) -> str:
    lines = [f"# {_markdown(manifest['case']['title'])}", "", "## Evidence", ""]
    for item in manifest["artifacts"]:
        lines.append(f"- **{_markdown(item['label'])}** · {item['size']} bytes · SHA-256 \x60{item['digest']}\x60")
        if item["parent_id"]:
            links = _markdown(as_json(item["source"]))
            lines.append(f"  - {_markdown(item['operation'])} from \x60{item['parent_id']}\x60 · {links}")
    lines.extend(["", "## Analysis", ""])
    for run in manifest["runs"]:
        lines.append(f"- {_markdown(run['kind'])} · {_markdown(run['status'])} · engine {_markdown(run['engine'])} · \x60{run['source_id']}\x60")
        if run["kind"] == "recipe":
            lines.append(f"  - {_markdown(run['details'].get('recipe', ''))}")
    for entry in manifest["inspections"]:
        for issue in entry["report"].get("issues", []):
            lines.append(f"- \x60{entry['artifact_id']}\x60 · {_markdown(issue)}")
    lines.extend(["", "## Notes", ""])
    superseded = {parent for revision in manifest["revisions"] for parent in revision["bases"]}
    for item in manifest["revisions"]:
        if item["id"] not in superseded:
            lines.append(f"- **{_markdown(item['author'])}** · {_markdown(item['body'])}")
            lines.append(f"  - {_markdown(as_json(item['anchor']))}")
    return "\n".join(lines) + "\n"


def export(workspace: Workspace, destination: str | Path) -> dict:
    manifest = workspace.manifest()
    with _publish_folder(destination) as folder:
        (folder / "case.json").write_text(as_json(manifest) + "\n", encoding="utf-8")
        (folder / "report.md").write_text(report_markdown(manifest), encoding="utf-8")
        with (folder / "timeline.jsonl").open("w", encoding="utf-8", newline="\n") as output:
            chronological = sorted(manifest["timeline"], key=lambda row: (
                row["seconds"] is None, row["seconds"] or 0, row["nanos"] or 0, row["id"]
            ))
            for record in chronological:
                entry = timesketch(record)
                if entry is not None:
                    output.write(as_json(entry) + "\n")
    return {"directory": str(Path(destination)), "artifacts": len(manifest["artifacts"])}


def _digest_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_checksums(folder: Path, name: str, files: list[str], algorithm: str) -> None:
    with (folder / name).open("w", encoding="utf-8", newline="\n") as stream:
        for item in sorted(files):
            stream.write(f"{_digest_file(folder / item, algorithm)}  {item}\n")


def pack(workspace: Workspace, destination: str | Path, *, include_files: bool = False) -> dict:
    manifest = workspace.manifest()
    manifest["includes_files"] = include_files
    with _publish_folder(destination) as folder:
        (folder / "bagit.txt").write_bytes(_LABEL.encode("ascii"))
        data = folder / "data"
        data.mkdir()
        case_data = as_json(manifest).encode("ascii") + b"\n"
        if len(case_data) > _MAX_MANIFEST:
            raise ValueError("Case metadata exceeds the package limit")
        (data / "case.json").write_bytes(case_data)
        files = ["data/case.json"]
        if include_files:
            (data / "objects").mkdir()
            seen = set()
            for record in manifest["artifacts"]:
                digest = record["digest"]
                if digest in seen:
                    continue
                payload = f"data/objects/{digest}"
                (folder / payload).write_bytes(workspace.blob(record))
                files.append(payload)
                seen.add(digest)
        tags = ["bagit.txt"]
        for algorithm in _ALGORITHMS:
            name = f"manifest-{algorithm}.txt"
            _write_checksums(folder, name, files, algorithm)
            tags.append(name)
        _write_checksums(folder, "tagmanifest-sha256.txt", tags, "sha256")
        check_pack(folder)
    return {"directory": str(Path(destination)), "included_files": include_files, "payloads": len(files)}


def _checksums(folder: Path, name: str, allowed: set[str], algorithm: str) -> dict[str, str]:
    digest_size = hashlib.new(algorithm).digest_size * 2
    pattern = re.compile(rf"([a-f0-9]{{{digest_size}}})  (\S+)\Z")
    entries = {}
    raw = read_file(folder / name, _MAX_MANIFEST).decode("ascii")
    for line in raw.splitlines():
        match = pattern.fullmatch(line)
        if not match or match[2] not in allowed or match[2] in entries:
            raise ValueError(f"Invalid path or duplicate entry in {name}")
        entries[match[2]] = match[1]
    if entries.keys() != allowed:
        raise ValueError(f"Missing entries in {name}")
    for path, digest in entries.items():
        if _digest_file(folder / path, algorithm) != digest:
            raise ValueError(f"Package checksum differs for {path}")
    return entries


def _safe_entries(folder: Path):
    for entry in folder.rglob("*"):
        if entry.is_symlink() or not entry.resolve().is_relative_to(folder):
            raise ValueError("Package contains an external or symbolic path")
        yield entry


def check_pack(source: str | Path) -> dict:
    folder = Path(source).resolve()
    if not folder.is_dir():
        raise ValueError("Package directory does not exist")
    actual = set()
    for path in _safe_entries(folder):
        relative = path.relative_to(folder).as_posix()
        if path.is_dir():
            if relative not in {"data", "data/objects"}:
                raise ValueError(f"Unexpected package directory: {relative}")
            continue
        if not path.is_file():
            raise ValueError("Package entries must be regular files")
        if relative.startswith("data/objects/") and path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("Package object exceeds the artifact size limit")
        actual.add(relative)
    tags = {"bagit.txt", *[f"manifest-{algorithm}.txt" for algorithm in _ALGORITHMS]}
    if not tags | {"tagmanifest-sha256.txt", "data/case.json"} <= actual:
        raise ValueError("Package is missing required files")
    if read_file(folder / "bagit.txt", 256).decode("ascii").splitlines() != _LABEL.splitlines():
        raise ValueError("Expected a CTF Toolkit BagIt 1.0 package")
    manifest = json.loads(read_file(folder / "data/case.json", _MAX_MANIFEST))
    _validate_manifest(manifest)
    expected = {"data/case.json"}
    sizes = {}
    for row in manifest["artifacts"]:
        digest, size = row["digest"], row["size"]
        if sizes.setdefault(digest, size) != size:
            raise ValueError("Package contains inconsistent object sizes")
        if manifest["includes_files"]:
            path = f"data/objects/{digest}"
            expected.add(path)
            if path not in actual or (folder / path).stat().st_size != size:
                raise ValueError(f"Package object size differs: {digest}")
    if actual != expected | tags | {"tagmanifest-sha256.txt"}:
        raise ValueError("Package has missing or unexpected payloads")
    _checksums(folder, "tagmanifest-sha256.txt", tags, "sha256")
    sha256_entries = _checksums(folder, "manifest-sha256.txt", expected, "sha256")
    for entry in expected - {"data/case.json"}:
        if sha256_entries[entry] != entry.rsplit("/", 1)[1]:
            raise ValueError(f"Package object has the wrong content address: {entry}")
    _checksums(folder, "manifest-sha512.txt", expected, "sha512")
    return manifest


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and ID.fullmatch(value) is not None


def _validate_record_shapes(manifest: dict) -> None:
    for table, columns, json_fields, keys in _RECORDS:
        rows = manifest.get(table)
        if not isinstance(rows, list):
            raise ValueError(f"Package is missing records for {table}")
        expected = set(columns) | ({"bases"} if table == "revisions" else set())
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or row.keys() != expected:
                raise ValueError(f"Malformed {table} record")
            key = tuple(row[column] for column in keys)
            if not all(_valid_id(value) for value in key) or key in seen:
                raise ValueError(f"Duplicate or malformed {table} identifier")
            seen.add(key)
            for column in json_fields:
                shape = list if column == "anchor" else dict
                if not isinstance(row[column], shape):
                    raise ValueError(f"Malformed {table}.{column}")


def _validate_manifest(manifest: object) -> None:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported package schema")
    info = manifest.get("case")
    if (not isinstance(info, dict) or not _valid_id(info.get("case_id"))
            or not isinstance(info.get("title"), str) or not info["title"].strip()
            or len(info["title"]) > 200 or type(manifest.get("includes_files")) is not bool):
        raise ValueError("Invalid case information")
    _validate_record_shapes(manifest)

    ancestors = {}
    run_keys = {row["id"] for row in manifest["runs"]}
    for row in manifest["artifacts"]:
        digest, size, label = row["digest"], row["size"], row["label"]
        if (not isinstance(digest, str) or not DIGEST.fullmatch(digest)
                or type(size) is not int or not 0 <= size <= MAX_ARTIFACT_BYTES
                or not isinstance(label, str) or not label.strip() or len(label) > 1024):
            raise ValueError("Invalid artifact metadata")
        parent = row["parent_id"]
        if parent is not None and (not _valid_id(parent) or parent not in ancestors):
            raise ValueError("Artifact lineage contains a missing or forward parent")
        run = row["run_id"]
        if run is not None and (not _valid_id(run) or run not in run_keys or parent is None):
            raise ValueError("Artifact operation refers to an unknown run")
        if row["operation"] not in {"import", "png_tail", "zip_member", "gzip_member",
                                    "b64d", "b64e", "hex_decode", "hex_encode"}:
            raise ValueError("Unknown operation in artifact lineage")
        ancestors[row["id"]] = row
    for row in manifest["runs"]:
        source = row["source_id"]
        if (not _valid_id(source) or source not in ancestors
                or row["kind"] not in {"analysis", "recipe"}
                or row["status"] not in {"complete", "partial"} or not isinstance(row["engine"], str)):
            raise ValueError("Invalid analysis run")
    for row in manifest["timeline"]:
        sec, nano = row["seconds"], row["nanos"]
        if sec is not None and (type(sec) is not int or not -62135596800 <= sec <= 253402300799):
            raise ValueError("Invalid timeline UTC seconds")
        if type(nano) is not int or not 0 <= nano < 1_000_000_000:
            raise ValueError("Invalid timeline nanoseconds")
        event = row["event"]
        if (event.get("seconds") != sec or event.get("nanos") != nano
                or type(event.get("precision")) is not int or not 0 <= event["precision"] <= 9
                or not isinstance(event.get("source"), dict)
                or not all(isinstance(event.get(field), str) for field in
                           ("message", "timestamp_desc", "original_time"))):
            raise ValueError("Invalid timeline event")

    notes = {}
    for revision in manifest["revisions"]:
        note_id = revision["note_id"]
        if (not _valid_id(note_id) or not note_body_valid(revision["body"], revision["author"])):
            raise ValueError("Invalid annotation revision")
        bases = revision["bases"]
        if (not isinstance(bases, list) or any(not _valid_id(base) or notes.get(base) != note_id for base in bases)
                or len(set(bases)) != len(bases)):
            raise ValueError("Annotation revision refers to an unknown parent")
        notes[revision["id"]] = note_id


def _merge_records(conn, manifest: dict, imported_by: str | None) -> int:
    inserted = 0
    conn.execute("PRAGMA defer_foreign_keys=ON")
    for table, columns, json_fields, keys in _RECORDS:
        lookup = f"SELECT * FROM {table} WHERE " + " AND ".join(f"{key}=?" for key in keys)
        add = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
        for row in manifest[table]:
            current = conn.execute(lookup, tuple(row[key] for key in keys)).fetchone()
            if current is not None:
                old = parse_row(current, *json_fields)
                differences = [key for key in columns if old[key] != row[key] and key != "imported_by"]
                if table == "revisions":
                    parents = conn.execute("SELECT parent_id FROM revision_parents WHERE revision_id=?", (row["id"],))
                    if sorted(parent["parent_id"] for parent in parents) != sorted(row["bases"]):
                        differences.append("bases")
                if differences:
                    raise ValueError(f"Conflicting stored {table} record")
                continue
            if table == "revisions":
                validate_anchors(conn, row["anchor"])
                row = {**row, "imported_by": imported_by if imported_by is not None else row["imported_by"]}
            conn.execute(add, tuple(as_json(row[key]) if key in json_fields else row[key] for key in columns))
            if table == "revisions":
                conn.executemany("INSERT INTO revision_parents VALUES (?, ?)",
                                 ((row["id"], base) for base in row["bases"]))
            inserted += 1
    if conn.execute("PRAGMA foreign_key_check").fetchone():
        raise ValueError("Package contains missing record references")
    return inserted


def _ingest(workspace: Workspace, source: Path, manifest: dict, imported_by: str | None) -> dict:
    with workspace.transaction(write=True) as conn:
        if conn.execute("SELECT case_id FROM metadata").fetchone()[0] != manifest["case"]["case_id"]:
            raise ValueError("Package is for a different case")
        inserted = _merge_records(conn, manifest, imported_by)
        restored = 0
        if manifest["includes_files"]:
            for digest in dict.fromkeys(record["digest"] for record in manifest["artifacts"]):
                present = workspace.blob_path(digest).is_file()
                raw = read_file(source / "data" / "objects" / digest)
                if hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError("Package object changed during import")
                workspace.write_blob(raw)
                restored += not present
        if inserted or restored:
            workspace.change(conn, "package", manifest["case"]["case_id"])
    return {"inserted": inserted, "restored_objects": restored, "included_files": manifest["includes_files"]}


def unpack(source: str | Path, destination: str | Path, imported_by: str | None = None) -> dict:
    source = Path(source).resolve()
    manifest = check_pack(source)
    with _publish_folder(destination) as directory:
        info = manifest["case"]
        workspace = Workspace.create(directory, info["title"], case_id=info["case_id"])
        return _ingest(workspace, source, manifest, imported_by)


def merge(workspace: Workspace, source: str | Path, imported_by: str | None = None) -> dict:
    source = Path(source).resolve()
    return _ingest(workspace, source, check_pack(source), imported_by)
