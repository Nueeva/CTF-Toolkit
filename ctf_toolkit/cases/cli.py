"""Public CLI entry points for case workspaces and the optional private host."""

from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

from . import exchange, operations
from .caesar import rank_caesar
from .notes import NoteConflict, save_note
from .store import Workspace, read_file
from .timeline import index_timeline, timeline


def configure(subparsers) -> None:
    case = subparsers.add_parser("case", help="Inspect, replay, and share a local evidence case")
    case.add_argument("--dir", type=Path, required=True, help="Case workspace directory")
    commands = case.add_subparsers(dest="action", required=True)
    commands.add_parser("init").add_argument("--title")
    commands.add_parser("add").add_argument("file", type=Path, nargs="+")
    show = commands.add_parser("show")
    show.add_argument("id", nargs="?")
    show.add_argument("--offset", type=int, default=0)
    commands.add_parser("analyze").add_argument("id")
    transform = commands.add_parser("transform")
    transform.add_argument("id")
    transform.add_argument("--recipe", required=True)
    transform.add_argument("--preview", action="store_true")
    verify = commands.add_parser("verify")
    verify.add_argument("--replay", action="store_true")
    commands.add_parser("export").add_argument("--out", type=Path, required=True)
    pack = commands.add_parser("pack")
    pack.add_argument("--out", type=Path, required=True)
    pack.add_argument("--with-files", action="store_true")
    for action in ("merge", "unpack"):
        parser = commands.add_parser(action)
        parser.add_argument("package", type=Path)
        parser.add_argument("--author", default=getpass.getuser())
    check = commands.add_parser("pack-check")
    check.add_argument("package", type=Path)
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8081)
    demo = commands.add_parser("demo")
    demo.add_argument("exercise", choices=["layered", "timeline", "caesar"])
    compare = commands.add_parser("compare")
    compare.add_argument("first")
    compare.add_argument("second")
    compare.add_argument("--offset-a", type=int, default=0)
    compare.add_argument("--offset-b", type=int, default=0)
    source = commands.add_parser("source")
    source.add_argument("id")
    source.add_argument("--start", type=int, required=True)
    source.add_argument("--stop", type=int, required=True)
    source.add_argument("--root", action="store_true", help="Trace provenance recursively to the root artifact")
    chronology = commands.add_parser("timeline")
    chronology.add_argument("id", nargs="?")
    chronology.add_argument("--profile", choices=["pcap", "access", "jsonl", "syslog", "csv"])
    chronology.add_argument("--timezone", help="Offset for a timestamp without one, for example +07:00")
    chronology.add_argument("--start", type=int, help="First UTC epoch second")
    chronology.add_argument("--stop", type=int, help="Last UTC epoch second")
    note = commands.add_parser("note")
    note.add_argument("--body", required=True)
    note.add_argument("--author", default=getpass.getuser())
    note.add_argument("--artifact")
    note.add_argument("--event", action="append", default=[])
    note.add_argument("--start", type=int)
    note.add_argument("--stop", type=int)
    note.add_argument("--note-id")
    note.add_argument("--base", action="append", default=[])
    caesar = commands.add_parser("caesar")
    caesar.add_argument("id")
    caesar.add_argument("--lang", choices=["id", "en"], required=True)

    doctor = subparsers.add_parser("doctor", help="Show version, Python, and available parser dependencies")
    doctor.add_argument("--json", action="store_true")
    team = subparsers.add_parser("team", help="Manage the optional private team host")
    team.add_argument("--dir", type=Path, required=True)
    actions = team.add_subparsers(dest="action", required=True)
    bootstrap = actions.add_parser("init")
    bootstrap.add_argument("--admin", required=True)
    host = actions.add_parser("serve")
    host.add_argument("--host", default="127.0.0.1")
    host.add_argument("--port", type=int, default=8443)
    host.add_argument("--origin", required=True, help="Public HTTPS origin of the host")
    host.add_argument("--cert", type=Path, required=True)
    host.add_argument("--key", type=Path, required=True)
    register = actions.add_parser("import")
    register.add_argument("package", type=Path)
    register.add_argument("--owner", required=True)
    merge = actions.add_parser("merge")
    merge.add_argument("id")
    merge.add_argument("package", type=Path)
    merge.add_argument("--actor", required=True)
    package = actions.add_parser("pack")
    package.add_argument("id")
    package.add_argument("--out", type=Path, required=True)
    package.add_argument("--with-files", action="store_true")


def _emit(data: object) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False))


def doctor(as_json: bool) -> int:
    from ctf_toolkit import __version__
    names = ("PIL", "dpkt", "cv2", "sqlite3")
    detected = {name: importlib.util.find_spec(name) is not None for name in names}
    result = {"toolkit": __version__, "python": sys.version.split()[0],
              "interpreter": sys.executable, "parsers_detected": detected}
    if as_json:
        _emit(result)
    else:
        print(f"CTF Toolkit {__version__}\nPython {result['python']} · {sys.executable}")
        for name, available in detected.items():
            print(f"{name}: {'detected' if available else 'missing'}")
    return 0


def _note(workspace: Workspace, args: argparse.Namespace) -> dict:
    anchors = [{"kind": "event", "id": value} for value in args.event]
    if args.artifact:
        artifact = {"kind": "artifact", "id": args.artifact}
        if args.start is not None or args.stop is not None:
            artifact.update(kind="bytes", start=args.start, stop=args.stop)
        anchors.append(artifact)
    elif args.start is not None or args.stop is not None:
        raise ValueError("Byte ranges require an artifact")
    return save_note(workspace, args.body, args.author, anchors=anchors or None,
                     note_id=args.note_id, bases=args.base)


def _case(args: argparse.Namespace) -> object:
    action = args.action
    if action == "init":
        return Workspace.create(args.dir, args.title).info()
    if action == "unpack":
        return exchange.unpack(args.package, args.dir, args.author)
    if action == "pack-check":
        package = exchange.check_pack(args.package)
        return {"ok": True, "case": package["case"], "included_files": package["includes_files"]}
    if action == "demo":
        from .demos import populate
        return populate(Workspace.create(args.dir), args.exercise)
    workspace = Workspace(args.dir)
    if action == "add":
        added = []
        with workspace.transaction(write=True) as conn:
            for path in args.file:
                item = workspace.insert_artifact(conn, read_file(path), path.name)
                workspace.change(conn, "artifact", item["id"])
                added.append(item)
        return added
    if action == "show":
        return operations.inspect_saved(workspace, args.id, args.offset) if args.id else workspace.snapshot()
    if action == "analyze":
        return operations.analyze(workspace, args.id)
    if action == "transform":
        return operations.transform(workspace, args.id, args.recipe, preview=args.preview)
    if action == "verify":
        return operations.verify(workspace, replay=args.replay)
    if action == "export":
        return exchange.export(workspace, args.out)
    if action == "pack":
        return exchange.pack(workspace, args.out, include_files=args.with_files)
    if action == "merge":
        return exchange.merge(workspace, args.package, args.author)
    if action == "compare":
        return operations.compare(workspace, args.first, args.second, args.offset_a, args.offset_b)
    if action == "source":
        return operations.source_region(workspace, args.id, args.start, args.stop, to_root=getattr(args, "root", False))
    if action == "timeline":
        if args.profile:
            if not args.id:
                raise ValueError("Indexing a timeline requires an artifact ID")
            return index_timeline(workspace, args.id, args.profile, args.timezone)
        return timeline(workspace, args.id, args.start, args.stop)
    if action == "note":
        return _note(workspace, args)
    if action == "caesar":
        raw = workspace.blob(workspace.artifact(args.id))
        return rank_caesar(raw.decode("utf-8"), args.lang)
    if action == "serve":
        from .local_web import serve
        serve(workspace, args.port)
        return None
    raise ValueError("Unknown case operation")


def execute(args: argparse.Namespace) -> int:
    try:
        if args.subcommand == "doctor":
            return doctor(args.json)
        if args.subcommand == "team":
            from .team_host import execute as execute_team
            return execute_team(args)
        result = _case(args)
        if result is not None:
            _emit(result)
        if args.action == "verify" and not result["ok"]:
            return 1
        return 0
    except NoteConflict as exc:
        print(json.dumps({"error": str(exc), "current": exc.current}, ensure_ascii=True), file=sys.stderr)
        return 1
    except (LookupError, ValueError, OSError, sqlite3.Error, TypeError, OverflowError, RecursionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
