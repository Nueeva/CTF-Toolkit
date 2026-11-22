"""Timeline indexing for offline capture files and structured logs."""

from __future__ import annotations

import io
import json
import re
import struct
import uuid
from datetime import datetime, timedelta, timezone

from ctf_toolkit.forensics.log_hunter import parse_access_log_line

from .store import Workspace, as_json, parse_row

MAX_EVENTS = 10_000
_PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
    b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9),
}
_ISO_TIMESTAMP = re.compile(
    r"(?P<clock>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)"
    r"(?:\.(?P<fraction>\d{1,9}))?(?P<zone>Z|[+-]\d\d:?\d\d)?\Z"
)
_LOG_TIME = re.compile(r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d\d:\d\d:\d\d) ([+-]\d{4})\Z")
_MONTHS = {name: month for month, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1
)}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _zone(text: str) -> timezone:
    if text == "Z":
        return timezone.utc
    if not re.fullmatch(r"[+-]\d\d:?\d\d", text):
        raise ValueError("Use UTC zone Z or an explicit offset such as +07:00")
    compact = text.replace(":", "")
    hours, minutes = int(compact[1:3]), int(compact[3:])
    if hours > 23 or minutes > 59:
        raise ValueError("UTC offset is out of range")
    sign = -1 if text[0] == "-" else 1
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def _timestamp(text: str, assumed_zone: str | None) -> dict:
    fields = _ISO_TIMESTAMP.fullmatch(text)
    if not fields:
        raise ValueError("Invalid ISO 8601 timestamp")
    clock = datetime.fromisoformat(fields["clock"])
    zone = fields["zone"] or assumed_zone
    fraction = fields["fraction"] or ""
    seconds = None
    if zone is not None:
        delta = clock.replace(tzinfo=_zone(zone)) - _EPOCH
        seconds = delta.days * 86400 + delta.seconds
    return {
        "seconds": seconds, "nanos": int(fraction.ljust(9, "0")), "precision": len(fraction),
        "zone": zone, "zone_assumed": bool(zone and not fields["zone"]), "original_time": text,
    }


def _pcap(data: bytes) -> tuple[list[dict], list[str]]:
    if len(data) < 24 or data[:4] not in _PCAP_FORMATS:
        raise ValueError("Expected a classic PCAP header")
    order, precision = _PCAP_FORMATS[data[:4]]
    major, minor, _, _, snaplen, link_type = struct.unpack_from(order + "HHIIII", data, 4)
    if (major, minor) != (2, 4) or snaplen == 0:
        raise ValueError("Unsupported PCAP header version or snaplen")
    position = 24
    events = []
    issues = []
    while position < len(data) and len(events) < MAX_EVENTS:
        if position + 16 > len(data):
            issues.append("Truncated PCAP frame header")
            break
        seconds, fraction, size, original_size = struct.unpack_from(order + "IIII", data, position)
        start = position + 16
        stop = start + size
        if stop > len(data) or size > snaplen or size > original_size or fraction >= 10**precision:
            issues.append("PCAP frame length or timestamp failed validation")
            break
        sequence = len(events) + 1
        events.append({
            "seconds": seconds, "nanos": fraction * 10**(9 - precision), "precision": precision,
            "original_time": f"{seconds}.{fraction:0{precision}d}", "zone": "Z",
            "zone_assumed": False, "message": f"Frame {sequence} · {size} captured bytes",
            "timestamp_desc": "packet captured", "link_type": link_type,
            "source": {"kind": "frame", "number": sequence, "start": start, "stop": stop},
        })
        position = stop
    if len(events) == MAX_EVENTS and position < len(data):
        issues.append(f"Timeline stopped at {MAX_EVENTS} events")
    return events, issues


_SYSLOG_3164 = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<clock>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<rest>.+)$"
)
_SYSLOG_5424 = re.compile(
    r"^(?:<\d+>1\s+)?(?P<iso>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:?\d\d)?)\s+(?P<host>\S+)\s+(?P<rest>.+)$"
)


def _log_event(text: str, profile: str, assumed_zone: str | None) -> dict:
    if profile == "jsonl":
        row = json.loads(text)
        if not isinstance(row, dict):
            raise ValueError("JSONL entry must be an object")
        fields = [row.get(key) for key in ("datetime", "message", "timestamp_desc")]
        if any(not isinstance(item, str) for item in fields):
            raise ValueError("JSONL expects datetime, message, and timestamp_desc strings")
        time, message, description = fields
        if not message.strip() or not description.strip():
            raise ValueError("Event message and timestamp description are required")
        return dict(_timestamp(time, assumed_zone), message=message, timestamp_desc=description)
    if profile == "syslog":
        stripped = text.strip()
        m5424 = _SYSLOG_5424.match(stripped)
        if m5424:
            iso_t = m5424.group("iso")
            msg = f"{m5424.group('host')} {m5424.group('rest').strip()}"
            return dict(_timestamp(iso_t, assumed_zone), message=msg, timestamp_desc="syslog event")
        m3164 = _SYSLOG_3164.match(stripped)
        if not m3164:
            raise ValueError("Expected RFC 3164 or RFC 5424 syslog line")
        month_num = _MONTHS.get(m3164.group("month").lower())
        if month_num is None:
            raise ValueError("Invalid syslog month")
        day_num = int(m3164.group("day"))
        clock = m3164.group("clock")
        year = datetime.now(timezone.utc).year
        iso_str = f"{year:04d}-{month_num:02d}-{day_num:02d}T{clock}"
        msg = f"{m3164.group('host')} {m3164.group('rest').strip()}"
        orig = f"{m3164.group('month')} {day_num:2d} {clock}"
        return dict(_timestamp(iso_str, assumed_zone), message=msg, timestamp_desc="syslog event", original_time=orig)
    if profile == "csv":
        import csv as _csv
        cols = next(_csv.reader([text.strip()]), [])
        if len(cols) < 2:
            raise ValueError("CSV line requires at least timestamp and message columns")
        if cols[0].strip().lower() in ("datetime", "timestamp", "time", "date"):
            raise ValueError("CSV header line")
        time_str = cols[0].strip()
        msg_str = cols[1].strip()
        desc_str = cols[2].strip() if len(cols) >= 3 and cols[2].strip() else "CSV record"
        if not msg_str:
            raise ValueError("CSV message column is empty")
        return dict(_timestamp(time_str, assumed_zone), message=msg_str, timestamp_desc=desc_str)
    row = parse_access_log_line(text)
    match = _LOG_TIME.fullmatch(row["time"]) if row else None
    if not match:
        raise ValueError("Expected a common HTTP access log entry")
    day, month, year, clock, zone = match.groups()
    month_number = _MONTHS.get(month.lower())
    if month_number is None:
        raise ValueError("Invalid access log month")
    time = f"{year}-{month_number:02d}-{int(day):02d}T{clock}{zone}"
    message = f'{row["ip"]} {row["method"]} {row["url"]} · {row["status"]}'
    return dict(
        _timestamp(time, None), message=message, timestamp_desc="HTTP request logged",
        original_time=row["time"],
    )


def collect_events(data: bytes, profile: str, assumed_zone: str | None = None) -> tuple[list[dict], list[str]]:
    if profile == "pcap":
        return _pcap(data)
    if profile not in {"access", "jsonl", "syslog", "csv"}:
        raise ValueError("Choose the pcap, access, jsonl, syslog, or csv timeline profile")
    if assumed_zone is not None:
        _zone(assumed_zone)
    events = []
    invalid = 0
    stream = io.BytesIO(data)
    for number, raw in enumerate(stream, 1):
        if len(events) >= MAX_EVENTS:
            break
        if not raw.strip():
            continue
        try:
            if len(raw) > 64 * 1024:
                raise ValueError("Log line exceeds 64 KiB")
            decoded_line = raw.decode("utf-8")
            if profile == "csv" and number == 1:
                import csv as _csv
                first_cols = next(_csv.reader([decoded_line.strip()]), [])
                if first_cols and first_cols[0].strip().lower() in ("datetime", "timestamp", "time", "date"):
                    continue
            event = _log_event(decoded_line, profile, assumed_zone)
        except (ValueError, OverflowError, RecursionError):
            invalid += 1
            continue
        event["source"] = {
            "kind": "line", "number": number, "start": stream.tell() - len(raw), "stop": stream.tell(),
        }
        events.append(event)
    issues = []
    if invalid:
        issues.append(f"{invalid} log lines could not be indexed")
    if len(events) == MAX_EVENTS:
        issues.append(f"Timeline indexing capped at {MAX_EVENTS} events")
    unzoned = sum(event["seconds"] is None for event in events)
    if unzoned:
        issues.append(f"{unzoned} events have an unspecified UTC offset")
    return events, issues


def index_timeline(workspace: Workspace, artifact_id: str, profile: str, assumed_zone: str | None = None) -> dict:
    artifact = workspace.artifact(artifact_id)
    entries, issues = collect_events(workspace.blob(artifact), profile, assumed_zone)
    with workspace.transaction(write=True) as conn:
        for event in entries:
            event_id = uuid.uuid5(uuid.UUID(artifact_id), f"{profile}:{event['source']['number']}").hex
            conn.execute(
                "INSERT INTO timeline VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "seconds=excluded.seconds, nanos=excluded.nanos, event=excluded.event",
                (event_id, artifact_id, event["seconds"], event["nanos"], as_json(event)),
            )
        workspace.change(conn, "timeline", artifact_id)
    return {"count": len(entries), "status": "partial" if issues else "complete", "issues": issues}


def timeline(workspace: Workspace, artifact_id: str | None = None, start: int | None = None,
             stop: int | None = None, limit: int | None = None, offset: int = 0) -> list[dict]:
    predicates = []
    params = []
    for clause, value in (("artifact_id = ?", artifact_id), ("seconds >= ?", start), ("seconds <= ?", stop)):
        if value is not None:
            predicates.append(clause)
            params.append(value)
    query = "SELECT * FROM timeline"
    if predicates:
        query += " WHERE " + " AND ".join(predicates)
    query += " ORDER BY seconds IS NULL, seconds, nanos, artifact_id, rowid"
    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])
    with workspace.transaction() as conn:
        return [parse_row(row, "event") for row in conn.execute(query, params)]


def timesketch(entry: dict) -> dict | None:
    event = entry["event"]
    if event["seconds"] is None:
        return None
    as_utc = _EPOCH + timedelta(seconds=event["seconds"])
    precision = event["precision"]
    fraction = ("." + f'{event["nanos"]:09d}'[:precision]) if precision else ""
    return {
        "datetime": as_utc.isoformat(timespec="seconds").removesuffix("+00:00") + fraction + "+00:00",
        "message": event["message"], "timestamp_desc": event["timestamp_desc"],
        "artifact_id": entry["artifact_id"], "source": event["source"],
    }
