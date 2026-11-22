"""Case analysis, derived pipelines, inspection, and integrity checks."""

from __future__ import annotations

import difflib
import json
import sqlite3
from dataclasses import dataclass

from .analysis import Extracted, inspect_artifact
from .store import Workspace, as_json, new_id, now
from .transforms import (
    ENGINE_VERSION, MAX_CHILDREN, MAX_DEPTH, MAX_DERIVED_BYTES, apply_recipe, base64_input_range,
    codec_input_range, parse_recipe, sha256,
)

PREVIEW_LIMIT = 4096


@dataclass
class AnalysisNode:
    data: bytes
    parent: int | None
    depth: int
    extracted: Extracted | None = None
    report: dict | None = None


def plan_analysis(data: bytes) -> list[AnalysisNode]:
    nodes = [AnalysisNode(data, None, 0)]
    remaining = MAX_DERIVED_BYTES
    for position, node in enumerate(nodes):
        available = (MAX_CHILDREN + 1 - len(nodes)) if node.depth < MAX_DEPTH else 0
        inspection = inspect_artifact(node.data, byte_budget=remaining, item_budget=available)
        node.report = inspection.report()
        for child in inspection.children:
            nodes.append(AnalysisNode(child.data, position, node.depth + 1, child))
            remaining -= len(child.data)
    return nodes


def analyze(workspace: Workspace, artifact_id: str) -> dict:
    nodes = plan_analysis(workspace.blob(workspace.artifact(artifact_id)))
    issues = sum(len(node.report["issues"]) for node in nodes)
    run_id = new_id()
    status = "partial" if issues else "complete"
    details = {"inspected": len(nodes), "issues": issues}
    saved_ids = [artifact_id]
    with workspace.transaction(write=True) as conn:
        conn.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, artifact_id, "analysis", status, ENGINE_VERSION, as_json(details), now()),
        )
        for index, node in enumerate(nodes):
            if index:
                origin = node.extracted
                child = workspace.insert_artifact(
                    conn, node.data, origin.label, parent_id=saved_ids[node.parent],
                    operation=origin.operation, run_id=run_id, source=origin.source,
                )
                saved_ids.append(child["id"])
            conn.execute("INSERT INTO inspections VALUES (?, ?, ?)",
                         (saved_ids[index], run_id, as_json(node.report)))
        workspace.change(conn, "analysis", run_id)
    return {"id": run_id, "status": status, "artifacts": saved_ids, **details}


def transform(workspace: Workspace, artifact_id: str, recipe: str, *, preview: bool = False) -> dict:
    source = workspace.artifact(artifact_id)
    original = workspace.blob(source)
    results = apply_recipe(original, recipe)
    details = {
        "recipe": " | ".join(parse_recipe(recipe)),
        "input_sha256": source["digest"], "output_sha256": sha256(results[-1].output),
    }
    if preview:
        steps = []
        before = original
        for step in results:
            steps.append({
                "operation": step.operation, "input": preview_bytes(before),
                "output": preview_bytes(step.output), "sha256": sha256(step.output),
            })
            before = step.output
        return {**details, "steps": steps}
    run_id = new_id()
    saved_ids = []
    parent_id = artifact_id
    with workspace.transaction(write=True) as conn:
        conn.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, artifact_id, "recipe", "complete", ENGINE_VERSION, as_json(details), now()),
        )
        for step in results:
            child = workspace.insert_artifact(
                conn, step.output, f"{step.operation} output", parent_id=parent_id,
                operation=step.operation, run_id=run_id, source=step.source,
            )
            parent_id = child["id"]
            saved_ids.append(parent_id)
        workspace.change(conn, "recipe", run_id)
    return {"id": run_id, "status": "complete", "artifacts": saved_ids, **details}


def preview_bytes(data: bytes, offset: int = 0) -> dict:
    if offset < 0 or offset > len(data):
        raise ValueError("Preview offset is outside the artifact")
    chunk = data[offset : offset + PREVIEW_LIMIT]
    return {"size": len(data), "offset": offset, "hex": chunk.hex(), "text": chunk.decode("utf-8", "replace")}


def inspect_saved(workspace: Workspace, artifact_id: str, offset: int = 0) -> dict:
    artifact = workspace.artifact(artifact_id)
    with workspace.transaction() as conn:
        row = conn.execute(
            "SELECT report FROM inspections WHERE artifact_id = ? ORDER BY rowid DESC LIMIT 1",
            (artifact_id,),
        ).fetchone()
    available = workspace.blob_path(artifact["digest"]).is_file()
    return {**artifact, "report": json.loads(row["report"]) if row else None,
            "preview": preview_bytes(workspace.blob(artifact), offset) if available else None}


_PROVENANCE_CODECS = {
    "b64d", "b64url_d", "b32d", "b32hex_d", "hex_decode", "b45d",
    "b85d", "z85d", "b36d", "b58d", "b58_ripple_d", "b62d", "a85d", "b91d",
    "rot13", "rot47", "atbash", "reverse",
}


def _single_hop_source(workspace: Workspace, artifact_id: str, start: int, stop: int) -> dict:
    artifact = workspace.artifact(artifact_id)
    if start < 0 or start >= stop or stop > artifact["size"]:
        raise ValueError("Selection is outside the artifact")
    if not artifact["parent_id"]:
        return {"artifact_id": artifact_id, "kind": "bytes", "start": start, "stop": stop}
    location = artifact["source"]
    parent_id = artifact["parent_id"]
    if artifact["operation"] in _PROVENANCE_CODECS:
        original = workspace.blob(workspace.artifact(parent_id))
        first, last = codec_input_range(artifact["operation"], original, start, stop)
        return {"artifact_id": parent_id, "kind": "bytes", "start": first, "stop": last}
    if location["kind"] == "bytes":
        base = location["start"]
        return {"artifact_id": parent_id, "kind": "bytes", "start": base + start, "stop": base + stop}
    return {"artifact_id": parent_id, **location}


def source_region(workspace: Workspace, artifact_id: str, start: int, stop: int, *, to_root: bool = False) -> dict:
    step = _single_hop_source(workspace, artifact_id, start, stop)
    if not to_root:
        return step
    chain = [step]
    curr_id = step["artifact_id"]
    while step.get("kind") == "bytes":
        artifact = workspace.artifact(curr_id)
        if not artifact["parent_id"]:
            break
        nxt = _single_hop_source(workspace, curr_id, step["start"], step["stop"])
        chain.append(nxt)
        step = nxt
        curr_id = step["artifact_id"]
    return {**step, "chain": chain}


def compare(workspace: Workspace, first: str, second: str, offset_a: int = 0, offset_b: int = 0) -> dict:
    a = inspect_saved(workspace, first, offset_a)
    b = inspect_saved(workspace, second, offset_b)
    if a["preview"] is None or b["preview"] is None:
        raise ValueError("Comparison needs both evidence files")
    left = bytes.fromhex(a["preview"]["hex"])
    right = bytes.fromhex(b["preview"]["hex"])
    # Anchor common edges before alignment. Matching repeated bytes inside the window
    # must not move a difference into an otherwise unchanged prefix or suffix.
    overlap = min(len(left), len(right))
    prefix = 0
    while prefix < overlap and left[prefix] == right[prefix]:
        prefix += 1
    suffix = 0
    while suffix < overlap - prefix and left[-1 - suffix] == right[-1 - suffix]:
        suffix += 1
    matcher = difflib.SequenceMatcher(
        None, left[prefix:len(left) - suffix], right[prefix:len(right) - suffix], autojunk=False
    )
    origin_a, origin_b = offset_a + prefix, offset_b + prefix
    differences = [
        {"kind": kind, "left": [origin_a + i, origin_a + j], "right": [origin_b + k, origin_b + l]}
        for kind, i, j, k, l in matcher.get_opcodes()
        if kind != "equal"
    ]
    structures = []
    for item in (a, b):
        report = item["report"]
        if report is None:
            report = inspect_artifact(workspace.blob(item), item_budget=0).report()
        structures.append(report["sections"])
    return {"left": a, "right": b, "differences": differences,
            "structures": {"left": structures[0], "right": structures[1]},
            "partial": len(left) != a["size"] or len(right) != b["size"]}


def _check_derived(artifact: dict, parent: dict) -> None:
    location = artifact["source"]
    if location["kind"] in {"bytes", "gzip_stream"}:
        start, stop = location["start"], location["stop"]
        if not 0 <= start <= stop <= parent["size"]:
            raise ValueError("Derivation has an invalid source range")
        if location["kind"] == "bytes" and artifact["size"] != stop - start:
            raise ValueError("Extracted artifact size does not match the source range")
    elif location["kind"] == "zip_member" and not 0 <= location["header_offset"] < parent["size"]:
        raise ValueError("ZIP member header is outside the source artifact")


def _replay_run(workspace: Workspace, run: dict, records: list[dict], source: dict) -> None:
    if run["engine"] != ENGINE_VERSION:
        raise ValueError(f"Replay requires case engine {run['engine']}")
    original = workspace.blob(source)
    if run["kind"] == "analysis":
        plan = plan_analysis(original)
        expected = [
            (node.extracted.operation, sha256(node.data), node.extracted.source, node.parent)
            for node in plan[1:]
        ]
    elif run["kind"] == "recipe":
        steps = apply_recipe(original, run["details"]["recipe"])
        expected = [(step.operation, sha256(step.output), step.source, i) for i, step in enumerate(steps)]
    else:
        raise ValueError(f"Unsupported run kind: {run['kind']}")
    identifiers = {item["id"]: i for i, item in enumerate([source, *records])}
    for i, (operation, digest, location, parent_index) in enumerate(expected):
        if i >= len(records):
            raise ValueError(f"Replay differs at step {i + 1}: output is missing")
        actual = records[i]
        if (actual["operation"], actual["digest"], actual["source"], identifiers.get(actual["parent_id"])) != (
            operation, digest, location, parent_index,
        ):
            raise ValueError(f"Replay differs at step {i + 1}")
    if len(records) != len(expected):
        raise ValueError(f"Replay has unexpected output at step {len(expected) + 1}")


def verify(workspace: Workspace, *, replay: bool = False) -> dict:
    manifest = workspace.manifest()
    artifacts = {item["id"]: item for item in manifest["artifacts"]}
    positions = {artifact_id: index for index, artifact_id in enumerate(artifacts)}
    checked: dict[str, int] = {}
    errors = []
    with workspace.transaction() as conn:
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            errors.append("SQLite integrity check failed")
        if conn.execute("PRAGMA foreign_key_check").fetchone():
            errors.append("SQLite references are inconsistent")
    for item in artifacts.values():
        try:
            digest = item["digest"]
            if digest not in checked:
                checked[digest] = len(workspace.blob(item))
            if checked[digest] != item["size"]:
                raise ValueError("Duplicate digest has inconsistent size metadata")
            if item["parent_id"] is not None:
                parent = artifacts[item["parent_id"]]
                if positions[parent["id"]] >= positions[item["id"]]:
                    raise ValueError("Derivation points forward in the artifact history")
                _check_derived(item, parent)
                location = item["source"]
                if location["kind"] == "bytes":
                    contents = workspace.blob(parent)
                    if sha256(contents[location["start"]:location["stop"]]) != digest:
                        raise ValueError("Stored output differs from the source byte range")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{item['id']}: {exc}")
    count = 0
    if replay and not errors:
        by_run: dict[str, list[dict]] = {}
        for item in artifacts.values():
            by_run.setdefault(item["run_id"], []).append(item)
        for run in manifest["runs"]:
            try:
                _replay_run(workspace, run, by_run.get(run["id"], []), artifacts[run["source_id"]])
                count += 1
            except (ValueError, OSError, KeyError, sqlite3.Error) as exc:
                errors.append(f"{run['id']}: {exc}")
    return {"ok": not errors, "checked_blobs": len(checked), "replayed_runs": count, "errors": errors}
