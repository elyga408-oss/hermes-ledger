"""``hermes ledger ...`` subcommands and the ``/ledger`` slash command."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

try:
    from . import ledger_core as core
    from .hooks import bind_check, default_ledger_dir
except ImportError:
    import ledger_core as core  # type: ignore[no-redef]
    from hooks import bind_check, default_ledger_dir  # type: ignore[no-redef]

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def _color(enabled: bool) -> Callable[[str, str], str]:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if enabled else text
    return paint


def _use_color(stream=sys.stdout) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


# --------------------------------------------------------------------------- argparse tree

def setup_argparse(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dir", help="ledger directory (default: <HERMES_HOME>/plugin-data/hermes-ledger)")
    subs = parser.add_subparsers(dest="ledger_command")

    v = subs.add_parser("verify", help="check the whole chain; exit 1 at the first broken entry")
    v.add_argument("--pubkey", help="pinned public key (base64 or a file); default: the local key")
    v.add_argument("--json", action="store_true", help="machine-readable output")

    s = subs.add_parser("show", help="readable timeline of recorded events")
    s.add_argument("--last", type=int, default=20, metavar="N", help="show the last N records (0 = all)")
    s.add_argument("--tool", help="only records for this tool")
    s.add_argument("--session", help="only records for this session id")
    s.add_argument("--kind", choices=core.KINDS, help="only records of this kind")
    s.add_argument("--json", action="store_true", help="print raw records as JSON lines")

    e = subs.add_parser("export", help="write a signed receipt for one session")
    e.add_argument("--receipt", action="store_true", required=True,
                   help="export a receipt (the only export format)")
    e.add_argument("--session", help="session id (default: the most recent session)")
    e.add_argument("--out", help="output file (default: stdout)")

    r = subs.add_parser("verify-receipt", help="verify a receipt with only a public key")
    r.add_argument("file")
    r.add_argument("--pubkey", help="pinned public key (base64 or a file)")
    r.add_argument("--json", action="store_true")

    subs.add_parser("key", help="print the public key and its id (never the private key)")

    n = subs.add_parser("note", help="append a signed human note to the ledger")
    n.add_argument("text", nargs="+")

    parser.set_defaults(func=handle)


def _ledger(args: argparse.Namespace) -> core.Ledger:
    d = getattr(args, "dir", None)
    return core.Ledger(Path(d).expanduser() if d else default_ledger_dir())


def handle(args: argparse.Namespace) -> int:
    cmd = getattr(args, "ledger_command", None)
    out = sys.stdout
    if cmd == "verify":
        return cmd_verify(_ledger(args), pubkey=args.pubkey, as_json=args.json, out=out)
    if cmd == "show":
        return cmd_show(_ledger(args), last=args.last, tool=args.tool, session=args.session,
                        kind=args.kind, as_json=args.json, out=out)
    if cmd == "export":
        return cmd_export(_ledger(args), session=args.session, out_path=args.out, out=out)
    if cmd == "verify-receipt":
        return cmd_verify_receipt(args.file, pubkey=args.pubkey, as_json=args.json, out=out)
    if cmd == "key":
        return cmd_key(_ledger(args), out=out)
    if cmd == "note":
        rec = _ledger(args).append("note", session="cli", note=" ".join(args.text))
        print(f"appended note as seq {rec['seq']}", file=out)
        return 0
    print("usage: hermes ledger {verify,show,export --receipt,verify-receipt,key,note}", file=out)
    return 2


# --------------------------------------------------------------------------- commands

def cmd_verify(led: core.Ledger, *, pubkey: Optional[str] = None, as_json: bool = False,
               out=sys.stdout) -> int:
    res = led.verify(pubkey)
    problems = bind_check(led.records()) if res.ok else []
    if problems:
        res.warnings.extend(problems)
    if as_json:
        print(json.dumps(res.to_dict(), indent=2), file=out)
        return 0 if res.ok else 1
    paint = _color(_use_color(out))
    if res.ok:
        print(paint("✔ " + res.summary(), GREEN), file=out)
    else:
        print(paint("✘ " + res.summary(), RED), file=out)
    for w in res.warnings:
        print(paint(f"  note: {w}", DIM), file=out)
    return 0 if res.ok else 1


def _short_time(ts: str) -> str:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%H:%M:%S")
    except (TypeError, ValueError):
        return str(ts)[:8]


def _detail(rec: dict, width: int = 70) -> str:
    kind = rec.get("kind")
    if kind == "tool_call":
        text = json.dumps(rec.get("args_redacted"), ensure_ascii=False, separators=(",", ":"))
    elif kind == "tool_result":
        bits = [rec.get("status") or "done"]
        if rec.get("duration_ms") is not None:
            bits.append(f"{rec['duration_ms']}ms")
        bits.append(f"sha256:{str(rec.get('result_sha256'))[:12]}")
        if rec.get("call_seq") is not None:
            bits.append(f"for #{rec['call_seq']}")
        if rec.get("approval_seq") is not None:
            bits.append(f"approved by #{rec['approval_seq']}")
        text = " ".join(bits)
    elif kind == "approval":
        a = rec.get("approval") or {}
        mark = "✔" if a.get("choice") in ("once", "session", "always") else "✘"
        text = f"{mark} {a.get('choice') or '?'} via {a.get('surface') or '?'}"
        if a.get("binds_seq") is not None:
            text += f" -> binds call #{a['binds_seq']}"
    else:
        text = str(rec.get("note") or "")
        if rec.get("args_redacted"):
            text += " " + json.dumps(rec["args_redacted"], ensure_ascii=False, separators=(",", ":"))
    return text if len(text) <= width else text[: width - 1] + "…"


def _short_session(session) -> str:
    text = str(session or "-")
    return text if len(text) <= 12 else text[:5] + "…" + text[-6:]


def render_rows(records: list[dict], color: bool = False) -> list[str]:
    paint = _color(color)
    rows = [paint(f"{'seq':>5}  {'time':8}  {'session':12}  {'kind':11}  {'tool':14}  detail", BOLD)]
    for r in records:
        rows.append(f"{r.get('seq', '?'):>5}  {_short_time(r.get('ts', '')):8}  "
                    f"{_short_session(r.get('session')):12}  {str(r.get('kind')):11}  "
                    f"{str(r.get('tool') or '-')[:14]:14}  {_detail(r)}")
    return rows


def select(records: list[dict], *, last: int = 20, tool: Optional[str] = None,
           session: Optional[str] = None, kind: Optional[str] = None) -> list[dict]:
    rows = [r for r in records
            if (not tool or r.get("tool") == tool)
            and (not session or r.get("session") == session)
            and (not kind or r.get("kind") == kind)]
    return rows[-last:] if last and last > 0 else rows


def cmd_show(led: core.Ledger, *, last: int = 20, tool: Optional[str] = None,
             session: Optional[str] = None, kind: Optional[str] = None, as_json: bool = False,
             out=sys.stdout) -> int:
    rows = select(led.records(), last=last, tool=tool, session=session, kind=kind)
    if as_json:
        for r in rows:
            print(json.dumps(r, ensure_ascii=False), file=out)
        return 0
    if not rows:
        print("ledger is empty (or nothing matches the filter)", file=out)
        return 0
    for line in render_rows(rows, color=_use_color(out)):
        print(line, file=out)
    return 0


def latest_session(records: list[dict]) -> Optional[str]:
    for r in reversed(records):
        if r.get("session") and r.get("session") != "cli":
            return r["session"]
    return None


def cmd_export(led: core.Ledger, *, session: Optional[str] = None, out_path: Optional[str] = None,
               out=sys.stdout) -> int:
    res = led.verify()
    if not res.ok:
        print(f"refusing to export: {res.summary()}", file=sys.stderr)
        return 1
    records = led.records()
    session = session or latest_session(records)
    if not session:
        print("no session found to export", file=sys.stderr)
        return 1
    receipt = core.build_receipt(records, session, led.keys, head=led.read_head())
    text = json.dumps(receipt, indent=2, ensure_ascii=False)
    if out_path:
        Path(out_path).write_text(text + "\n", encoding="utf-8")
        s = receipt["summary"]
        print(f"wrote receipt for session {session}: {s['records']} records "
              f"(seq {receipt['range'][0]}..{receipt['range'][1]}), key {receipt['key_id']} "
              f"-> {out_path}", file=out)
    else:
        print(text, file=out)
    return 0


def cmd_verify_receipt(path: str, *, pubkey: Optional[str] = None, as_json: bool = False,
                       out=sys.stdout) -> int:
    try:
        receipt = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"✘ cannot read receipt: {exc}", file=out)
        return 1
    res = core.verify_receipt(receipt, pubkey)
    if as_json:
        print(json.dumps(res.to_dict(), indent=2), file=out)
        return 0 if res.ok else 1
    paint = _color(_use_color(out))
    if res.ok:
        s = receipt.get("summary") or {}
        print(paint(f"✔ receipt valid: session {receipt.get('session')}, {res.count} records, "
                    f"key {res.key_id}", GREEN), file=out)
        if s.get("tools"):
            print("  tools: " + ", ".join(f"{k} x{v}" for k, v in sorted(s["tools"].items())), file=out)
    else:
        print(paint("✘ receipt " + res.summary(), RED), file=out)
    for w in res.warnings:
        print(paint(f"  note: {w}", DIM), file=out)
    return 0 if res.ok else 1


def cmd_key(led: core.Ledger, out=sys.stdout) -> int:
    keys = led.keys
    print(f"public key: {keys.public_b64}", file=out)
    print(f"key id:     {keys.key_id}", file=out)
    print(f"stored in:  {led.dir}", file=out)
    return 0


# --------------------------------------------------------------------------- /ledger

def slash_command(raw_args: str, ledger_dir: Optional[Callable[[], Path]] = None) -> str:
    """``/ledger`` (status + last 10), ``/ledger verify``, ``/ledger show [N]``."""
    led = core.Ledger((ledger_dir or default_ledger_dir)())
    parts = (raw_args or "").split()
    res = led.verify()
    status = ("✔ " if res.ok else "✘ ") + res.summary()
    if parts[:1] == ["verify"]:
        return status
    n = 10
    if parts[:1] == ["show"] and len(parts) > 1 and parts[1].isdigit():
        n = int(parts[1])
    rows = render_rows(select(led.records(), last=n))
    return "\n".join([status, "", *rows]) if len(rows) > 1 else status
