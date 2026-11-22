from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf_toolkit.cases import exchange, operations
from ctf_toolkit.cases.analysis import inspect_artifact
from ctf_toolkit.cases.caesar import rank_caesar
from ctf_toolkit.cases.demos import layered_png, populate
from ctf_toolkit.cases.notes import NoteConflict, save_note
from ctf_toolkit.cases.store import Workspace, new_id
from ctf_toolkit.cases.timeline import index_timeline, timeline
from ctf_toolkit.cases.transforms import sha256
from ctf_toolkit.crypto.classical import caesar_encrypt
from scripts.case_benchmark import corpus, archive

ROOT = Path(__file__).resolve().parents[2]


def invoke(*args, cwd=ROOT, expected=0, input=None):
    result = subprocess.run(
        [sys.executable, "-B", "-m", "ctf_toolkit", *map(str, args)],
        input=input, capture_output=True, cwd=cwd, timeout=45,
        env=dict(os.environ, PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8"),
    )
    assert result.returncode == expected, result.stderr.decode("utf-8", "replace")
    return result


def run_case(directory, *arguments):
    return json.loads(invoke("case", "--dir", directory, *arguments).stdout)


def test_layered_investigation_reopens_across_cli_processes(tmp_path):
    source = tmp_path / "original.png"
    source.write_bytes(layered_png())
    destination = tmp_path / "case with spaces"
    run_case(destination, "init", "--title", "Review")
    original, = run_case(destination, "add", source)
    source.rename(tmp_path / "moved.png")
    report = run_case(destination, "analyze", original["id"])
    assert report["status"] == "complete"
    _, zip_id, first, second = report["artifacts"]
    initial = run_case(destination, "show", zip_id)
    assert initial["source"] == {"kind": "bytes", "start": 69, "stop": original["size"]}
    roots = [run_case(destination, "show", member) for member in (first, second)]
    assert [root["source"]["name"] for root in roots] == ["desk/message.b64", "archive/copy.b64"]
    assert roots[0]["digest"] == roots[1]["digest"]
    assert roots[0]["id"] != roots[1]["id"]
    assert roots[0]["source"]["header_offset"] != roots[1]["source"]["header_offset"]

    left = run_case(destination, "transform", first, "--recipe", "b64d")
    right = run_case(destination, "transform", second, "--recipe", "b64d")
    assert left["output_sha256"] == right["output_sha256"] == sha256(b"hello")
    source_range = run_case(destination, "source", left["artifacts"][0], "--start", 3, "--stop", 5)
    assert source_range == {"artifact_id": first, "kind": "bytes", "start": 4, "stop": 8}
    outcome = run_case(destination, "verify", "--replay")
    assert outcome == {"ok": True, "checked_blobs": 4, "replayed_runs": 3, "errors": []}


@pytest.mark.parametrize("fixture", corpus(), ids=lambda fixture: fixture.name)
def test_fixed_format_corpus(fixture):
    report = inspect_artifact(fixture.raw)
    confirmed_binary = report.confidence == "confirmed" and report.format in {"png", "zip", "gzip"}
    assert (report.format if confirmed_binary else None) == fixture.format
    assert sorted(report.encodings) == sorted(fixture.encodings)
    if len(fixture.encodings) > 1:
        assert report.report()["encoding_status"] == "ambiguous"


def test_analysis_budget_leaves_an_explicit_partial_result(tmp_path, monkeypatch):
    work = Workspace.create(tmp_path / "limits")
    main = work.add("small archive.zip", archive(("early.txt", b"hello!"), ("later.txt", b"another note")))
    monkeypatch.setattr(operations, "MAX_DERIVED_BYTES", 8)
    run = operations.analyze(work, main["id"])
    assert run["status"] == "partial"
    assert len(run["artifacts"]) == 2
    inspected = operations.inspect_saved(work, main["id"])
    assert "later.txt" in inspected["report"]["issues"][0]
    limited_gzip = inspect_artifact(gzip.compress(b"archived records\n" * 7), byte_budget=20)
    assert limited_gzip.children == []
    assert limited_gzip.issues == ["GZIP member exceeds the remaining byte budget"]


def test_copy_without_bytes_still_supports_review_and_atomic_corruption_rejection(tmp_path):
    original = Workspace.create(tmp_path / "case")
    root = populate(original, "layered")[0]
    operations.analyze(original, root["id"])
    package = tmp_path / "review"
    exchange.pack(original, package)
    received = tmp_path / "received"
    exchange.unpack(package, received)
    reviewer = Workspace(received)
    assert operations.inspect_saved(reviewer, root["id"])["preview"] is None
    note = save_note(reviewer, "Header shows the archive at the end", "Reviewer",
                     anchors=[{"kind": "bytes", "id": root["id"], "start": 69, "stop": 70}])
    sent = tmp_path / "reply"
    exchange.pack(reviewer, sent)
    assert exchange.merge(original, sent, "Workspace owner")["inserted"] == 1
    assert original.snapshot()["notes"] == [dict(note, imported_by="Workspace owner")]
    before = original.manifest()
    (sent / "data" / "case.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="package schema"):
        exchange.merge(original, sent)
    assert original.manifest() == before


def test_offline_branch_conflict_and_duplicate_import(tmp_path):
    anchor = Workspace.create(tmp_path / "left")
    sample = anchor.add("note.txt", b"Two reviewers")
    evidence = [{"kind": "artifact", "id": sample["id"]}]
    seed = save_note(anchor, "Original", "lead", anchors=evidence)
    package = tmp_path / "initial"
    exchange.pack(anchor, package, include_files=True)
    exchange.unpack(package, tmp_path / "right")
    peer = Workspace(tmp_path / "right")
    assert operations.verify(peer, replay=True)["ok"]

    changes = {"note_id": seed["note_id"], "bases": [seed["id"]]}
    mine = save_note(anchor, "First reviewer", "lead", **changes)
    theirs = save_note(peer, "Second reviewer", "peer", **changes)
    reply = tmp_path / "reply"
    exchange.pack(peer, reply)
    assert exchange.merge(anchor, reply, "lead")["inserted"] == 1
    assert exchange.merge(anchor, reply, "lead") == {
        "inserted": 0, "restored_objects": 0, "included_files": False,
    }
    assert {row["body"] for row in anchor.snapshot()["notes"]} == {"First reviewer", "Second reviewer"}
    with pytest.raises(NoteConflict):
        save_note(anchor, "Stale", "lead", **changes)
    resolved = save_note(anchor, "Resolved", "lead", note_id=seed["note_id"], bases=[mine["id"], theirs["id"]])
    assert anchor.snapshot()["notes"] == [resolved]
    verification = operations.verify(anchor, replay=True)
    assert verification["ok"]


def test_full_package_validates_through_independent_bagit_and_detects_modified_blob(tmp_path):
    bagit = pytest.importorskip("bagit")
    work = Workspace.create(tmp_path / "source")
    sample = work.add("exhibit.txt", b"original bytes")
    path = tmp_path / "bag"
    exchange.pack(work, path, include_files=True)
    assert bagit.Bag(str(path)).validate()
    other = tmp_path / "copy"
    exchange.unpack(path, other)
    imported = Workspace(other)
    imported.blob_path(sample["digest"]).write_bytes(b"altered bytes")
    result = operations.verify(imported, replay=True)
    assert result["ok"] is False
    assert "failed verification" in result["errors"][0]


def test_notes_retry_returns_same_revision(tmp_path):
    work = Workspace.create(tmp_path)
    artifact = work.add("evidence", b"notes")
    anchor = [{"kind": "artifact", "id": artifact["id"]}]
    key = new_id()
    result = save_note(work, "Draft", "reader", anchors=anchor, request_id=key)
    assert save_note(work, "Draft", "reader", anchors=anchor, request_id=key) == result
    assert work.snapshot()["notes"] == [result]
    with pytest.raises(ValueError, match="different edit"):
        save_note(work, "New draft", "reader", anchors=anchor, request_id=key)


def test_timeline_filters_preserve_original_range_and_nanos(tmp_path):
    work = Workspace.create(tmp_path / "timeline")
    pcap, log, notes = populate(work, "timeline")
    assert index_timeline(work, pcap["id"], "pcap")["count"] == 2
    assert index_timeline(work, log["id"], "access")["count"] == 2
    result = index_timeline(work, notes["id"], "jsonl")
    assert result["status"] == "partial"
    event, = timeline(work, notes["id"])
    assert event["seconds"] is None
    index_timeline(work, notes["id"], "jsonl", "+07:00")
    selected = timeline(work, start=1795230900, stop=1795230900)
    assert [(item["seconds"], item["nanos"]) for item in selected] == [(1795230900, n) for n in (0, 0, 0, 1, 2)]
    frame_source = selected[-1]["event"]["source"]
    frame = work.blob(pcap)[frame_source["start"]:frame_source["stop"]]
    assert frame.endswith(b"training")
    assert frame_source["number"] == 2
    assert timeline(work, notes["id"])[0]["id"] == event["id"]
    path = tmp_path / "report"
    exchange.export(work, path)
    exported = [json.loads(row) for row in (path / "timeline.jsonl").read_text().splitlines()]
    assert exported[-1]["datetime"].endswith(".000000002+00:00")


def test_temporary_failure_publishes_no_case_records(tmp_path):
    work = Workspace.create(tmp_path)
    with pytest.raises(RuntimeError):
        with work.transaction(write=True) as conn:
            work.insert_artifact(conn, b"uncommitted", "sample")
            raise RuntimeError("interrupted")
    assert work.snapshot()["artifacts"] == []
    assert operations.verify(work)["checked_blobs"] == 0
    assert work.add("retried", b"uncommitted")["size"] == 11


def test_cli_triage_explicit_source_contract(tmp_path):
    file = tmp_path / "test data.txt"
    file.write_text("hello", encoding="ascii")
    assert json.loads(invoke("triage", "--file", file, "--json").stdout)["target_type"] == file.name
    literal = json.loads(invoke("triage", "--string", file, "--json").stdout)
    assert literal["target_type"] == "cli_arg"
    assert json.loads(invoke("triage", "literal", "--json").stdout)["target_type"] == "cli_raw"
    for invalid in (tmp_path, tmp_path / "missing.txt"):
        failure = invoke("triage", "--file", invalid, "--json", expected=1)
        assert not failure.stdout
        assert b"Expected a readable file" in failure.stderr
    assert b"not allowed" in invoke("triage", file, "--string", "literal", expected=2).stderr


def test_studio_exports_before_done_and_verifies_binary_replay(tmp_path):
    # Test the studio directly through its interactive function, then execute the generated script.
    test = (
        "from ctf_toolkit.ui.workbench.menu import recipe_studio_interactive as studio; studio()"
    )
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8")
    result = subprocess.run([sys.executable, "-B", "-c", test], cwd=tmp_path,
                            input=b"AP8=\n+ b64d\nexport\n0\n", capture_output=True, env=env, timeout=30)
    assert result.returncode == 0, result.stderr
    script = tmp_path / "solve_default_case.py"
    assert script.exists()
    assert "AP8=" not in script.read_text(encoding="utf-8")
    assert "Output SHA-256" in (tmp_path / "WRITEUP_default_case.md").read_text(encoding="utf-8")
    replay = subprocess.run([sys.executable, "-B", str(script), "--data", "AP8="], cwd=tmp_path,
                            capture_output=True, env=env, timeout=30)
    assert replay.returncode == 0, replay.stderr
    assert replay.stdout == b"\x00\xff"
    invalid = subprocess.run([sys.executable, "-B", str(script), "--data", "Zm9v"], cwd=tmp_path,
                             capture_output=True, env=env, timeout=30)
    assert invalid.returncode == 1 and b"Input SHA-256 differs" in invalid.stderr
    assert not invalid.stdout


_HOLDOUT = {
    "id": [
        "Penjaga gedung menemukan lencana warna biru di dekat tangga.",
        "Surat dengan tulisan tangan itu dilipat menjadi empat bagian.",
        "Jadwal kegiatan berubah karena ruangan utama sedang dicat.",
        "Kamera merekam sepeda merah melintas sebelum pintu dibuka.",
        "Pemandu menunjukkan batu tua yang pernah dipakai sebagai penanda.",
        "Tukang roti mulai bekerja saat jalanan masih sepi.",
        "Perjalanan menuju pulau kecil membutuhkan waktu dua jam.",
        "Peserta lomba menerima nomor dan petunjuk melalui surat elektronik.",
        "Di belakang lukisan ada tanda kecil yang sulit terlihat.",
        "Ketua kelompok meminta semua orang membawa alat tulis sendiri.",
        "Setumpuk piring bersih telah disusun di rak paling atas.",
        "Perawat memindahkan tanaman ke jendela agar terkena cahaya.",
        "Kami menunggu di halte hingga kendaraan berwarna kuning datang.",
        "Tetangga menemukan kunci perak di bawah bangku panjang.",
        "Lapangan penuh genangan setelah hujan turun tanpa henti.",
        "Mereka memasang papan petunjuk baru di dekat persimpangan.",
        "Esok sore pembicara akan membahas bangunan bersejarah itu.",
        "Sepasang burung hinggap di pagar ketika suara bel terdengar.",
        "Berkas foto dipindahkan ke folder terpisah sesuai tanggal.",
        "Nenek menulis resep kue pada kertas putih bergaris tipis.",
    ],
    "en": [
        "The night watch found a blue badge beside the staircase.",
        "A handwritten letter had been folded into four sections.",
        "The program changed because the main hall was being painted.",
        "The camera captured a red bicycle before the doors opened.",
        "The guide pointed to an old stone that once marked the boundary.",
        "The baker arrived for work while the streets were still quiet.",
        "The small ferry reached the island after a two hour crossing.",
        "Every runner received a number and directions by email.",
        "Someone left a tiny mark on the back of the painting.",
        "The workshop leader asked everyone to bring a pen.",
        "Clean plates were stacked along the highest shelf.",
        "The caretaker moved a plant closer to the sunny window.",
        "We waited at the stop until a yellow bus appeared.",
        "A neighbor found a silver key beneath the wooden bench.",
        "The field was covered in puddles after the storm.",
        "The workers installed a new sign beside the crossroads.",
        "Tomorrow the speaker will discuss the history of that building.",
        "Two birds landed on the fence when the bell rang.",
        "The photographs were filed in folders according to their dates.",
        "Her grandmother wrote a cake recipe on a sheet of lined paper.",
    ],
}


@pytest.mark.parametrize("language", ["id", "en"])
def test_caesar_on_separate_language_holdouts(language):
    correct = 0
    for index, plaintext in enumerate(_HOLDOUT[language]):
        shift = (index * 7 + 3) % 26
        ranking = rank_caesar(caesar_encrypt(plaintext, shift), language)
        assert not ranking["limited_evidence"]
        correct += any(candidate["text"] == plaintext and candidate["shift"] == shift
                       for candidate in ranking["candidates"])
    assert correct >= 18


@pytest.mark.parametrize("text", ["a", "aba", "Halo", "bye", "Q!Z", "io", "yes", "hi all"])
def test_short_caesar_reports_limited_evidence(text):
    report = rank_caesar(text, "id")
    assert report["limited_evidence"]
    assert len(report["candidates"]) == 3


def test_concatenated_gzip_records_each_source_range(tmp_path):
    work = Workspace.create(tmp_path)
    chunks = (gzip.compress(b"first\n", mtime=0), gzip.compress(b"second\n", mtime=0))
    root = work.add("two-members.gz", b"".join(chunks))
    plan = operations.analyze(work, root["id"])
    first, second = [work.artifact(identifier) for identifier in plan["artifacts"][1:]]
    assert [work.blob(item) for item in (first, second)] == [b"first\n", b"second\n"]
    assert first["source"] == {"kind": "gzip_stream", "start": 0, "stop": len(chunks[0])}
    assert second["source"]["start"] == len(chunks[0])
    assert operations.verify(work, replay=True)["ok"]


def test_comparison_identifies_an_insertion_and_zip_structure(tmp_path):
    work = Workspace.create(tmp_path)
    before = work.add("old.txt", b"status log ready")
    after = work.add("new.txt", b"status new log ready")
    result = operations.compare(work, before["id"], after["id"])
    assert result["differences"] == [{"kind": "insert", "left": [7, 7], "right": [7, 11]}]
    old_zip = work.add("old.zip", archive(("memo.txt", b"draft")))
    new_zip = work.add("new.zip", archive(("memo.txt", b"draft"), ("note.txt", b"ready")))
    structure = operations.compare(work, old_zip["id"], new_zip["id"])["structures"]
    assert [entry["name"] for entry in structure["left"]] == ["Central directory", "memo.txt"]
    assert [entry["name"] for entry in structure["right"]] == ["Central directory", "memo.txt", "note.txt"]
