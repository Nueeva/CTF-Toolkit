"""Measure classification on a fixed corpus of 36 deterministic file fixtures."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import statistics
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

# Also allow python scripts/case_benchmark.py from an unpacked source tree.
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ctf_toolkit.cases.analysis import inspect_artifact
from ctf_toolkit.cases.demos import layered_png
from ctf_toolkit.triage import triage_data


@dataclass(frozen=True)
class Fixture:
    name: str
    raw: bytes
    group: str
    format: str | None
    encodings: tuple[str, ...] = ()


def archive(*entries: tuple[str, bytes]) -> bytes:
    shell = io.BytesIO()
    with zipfile.ZipFile(shell, "w") as container:
        for name, data in entries:
            container.writestr(zipfile.ZipInfo(name), data)
    return shell.getvalue()


def corpus() -> list[Fixture]:
    layered = layered_png()
    png = layered[:69]
    zip_body = archive(("note.txt", b"ordinary file\n"))
    gzip_body = gzip.compress(b"a dated inventory entry\n", mtime=0)
    cases = {
        "valid": [
            ("png", png, "png"),
            ("zip", zip_body, "zip"),
            ("empty_zip", archive(), "zip"),
            ("gzip", gzip_body, "gzip"),
            ("plain_utf8", "Catatan barang ☕".encode(), None),
            ("plain_log", b"2026-11-21T04:10:00Z status=ready", None),
            ("short_base64", b"aGVsbG8=", None, ("base64",)),
            ("single_byte_base64", b"Zg==", None, ("base64",)),
            ("newline_base64", b"aGVs\r\nbG8=", None, ("base64",)),
            ("hex", b"666f6f", None, ("hex",)),
            ("spaced_hex", b"6f 6e 65", None, ("hex",)),
            ("empty_text", b"", None),
        ],
        "negative": [
            ("truncated_png", png[:20], None),
            ("png_without_end", png[:-12], None),
            ("bad_png_crc", png[:-1] + b"\0", None),
            ("truncated_zip", zip_body[:24], None),
            ("marker_in_text", b"Invoice note PK\x03\x04 text", None),
            ("zip_marker_only", b"PK\x03\x04", None),
            ("truncated_gzip", gzip_body[:-5], None),
            ("fake_gzip", b"\x1f\x8b\x08\0broken", None),
            ("bad_base64_padding", b"aaaa====BBBBcccc", None),
            ("odd_hex", b"abcde", None),
            ("invalid_base64_delimiter", b"aGVsbG8^=", None),
            ("binary_noise", b"\x00\xff\x11\xce\xba\x02\xbc", None),
        ],
        "ambiguous_or_layered": [
            ("hex_base64_overlap", b"4040404040404040", None, ("base64", "hex")),
            ("short_overlap", b"deadbeef", None, ("base64", "hex")),
            ("uppercase_overlap", b"BABEFACE", None, ("base64", "hex")),
            ("hex_with_spaces", b"40 40 40 40", None, ("base64", "hex")),
            ("ascii_plausible_base64", b"abcdefghijklmnop", None, ("base64",)),
            ("png_zip", layered, "png"),
            ("png_gzip", png + gzip_body, "png"),
            ("png_plain_trailer", png + b"draft note!", "png"),
            ("zip_in_zip", archive(("inner.zip", zip_body)), "zip"),
            ("gzip_of_zip", gzip.compress(zip_body, mtime=0), "gzip"),
            ("zip_of_gzip", archive(("log.gz", gzip_body)), "zip"),
            ("two_zip_members", archive(("first.txt", b"same"), ("second.txt", b"same")), "zip"),
        ],
    }
    return [Fixture(name, raw, group, kind, tuple(tags[0]) if tags else ())
            for group, rows in cases.items() for name, raw, kind, *tags in rows]


def _legacy(raw: bytes) -> tuple[str | None, tuple[str, ...], bool]:
    report = triage_data(raw)
    name = (report.magic_type or "").lower()
    kind = next((item for item in ("png", "zip", "gzip") if name.startswith(item)), None)
    embedded = any("embedded zip detected" in hint.lower() for hint in report.suggestions)
    encoding = {"Hexadecimal": "hex", "Base64": "base64"}
    codes = tuple(sorted(encoding[item] for item in report.encodings_detected if item in encoding))
    return kind, codes, embedded


def _revised(raw: bytes) -> tuple[str | None, tuple[str, ...], bool]:
    report = inspect_artifact(raw)
    recognized = report.format in {"png", "zip", "gzip"} and report.confidence == "confirmed"
    return report.format if recognized else None, tuple(sorted(report.encodings)), False


def peak_rss_bytes() -> int:
    if sys.platform != "win32":
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(rss if sys.platform == "darwin" else rss * 1024)
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("faults", wintypes.DWORD),
                    ("peak_working_set", ctypes.c_size_t), ("remainder", ctypes.c_size_t * 7)]

    counters = Counters()
    counters.size = ctypes.sizeof(counters)
    get_process = ctypes.windll.kernel32.GetCurrentProcess
    get_process.restype = wintypes.HANDLE
    read_counters = ctypes.windll.psapi.GetProcessMemoryInfo
    read_counters.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    if not read_counters(get_process(), ctypes.byref(counters), counters.size):
        raise OSError("Could not obtain peak working set")
    return counters.peak_working_set


def measure(engine: str, repeats: int) -> dict:
    check = {"legacy": _legacy, "v5": _revised}[engine]
    fixtures = corpus()
    samples = []
    results = {}
    for _ in range(repeats):
        for fixture in fixtures:
            start = time.perf_counter_ns()
            results[fixture.name] = check(fixture.raw)
            samples.append((time.perf_counter_ns() - start) / 1_000_000)
    kind_matches = sum(results[row.name][0] == row.format for row in fixtures)
    exact_matches = sum(results[row.name][:2] == (row.format, tuple(sorted(row.encodings))) for row in fixtures)
    false_confirmations = [row.name for row in fixtures if row.group == "negative"
                           and (results[row.name][0] or results[row.name][2])]
    needs_review = sum(bool(found[1]) for found in results.values())
    return {
        "engine": engine, "fixtures": len(fixtures), "format_matches": kind_matches,
        "exact_matches": exact_matches, "negative_false_confirmations": false_confirmations,
        "encoding_candidates_for_review": needs_review, "p95_ms": statistics.quantiles(samples, n=20)[18],
        "peak_rss_bytes": peak_rss_bytes(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["legacy", "v5"], required=True)
    parser.add_argument("--repeats", type=int, default=10)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    print(json.dumps(measure(args.engine, args.repeats), indent=2))


if __name__ == "__main__":
    main()
