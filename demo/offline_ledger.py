#!/usr/bin/env python3
"""Run the `hermes ledger` commands without Hermes, against any ledger directory.

    python3 demo/offline_ledger.py --dir /tmp/ledger verify

Also `simulate`: drive the plugin's hooks with the payloads Hermes sends for a
small agent run (session start, three tool calls, one approved command).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli  # noqa: E402
from hooks import Recorder  # noqa: E402


def simulate(directory: Path) -> None:
    rec = Recorder(directory)
    s = "demo-session"
    rec.on_session_start(session_id=s, model="demo-model", platform="cli")
    steps = [
        ("terminal", {"command": "ls -1 notes"}, '{"output": "plan.md\\ntodo.md"}', None),
        ("read_file", {"path": "notes/todo.md"}, "- ship the demo", None),
        ("terminal", {"command": "rm -r notes/old-drafts"}, '{"output": ""}', "once"),
        ("web_search", {"query": "release checklist", "api_key": "not-a-real-key"},
         '{"results": []}', None),
    ]
    for i, (tool, args, result, approve) in enumerate(steps, start=1):
        ids = dict(session_id=s, task_id=s, tool_call_id=f"call-{i}", turn_id="turn-1")
        rec.on_pre_tool_call(tool_name=tool, args=args, **ids)
        if approve:
            rec.on_post_approval_response(command=args["command"], description="recursive delete",
                                          pattern_key="rm_recursive", session_key=s,
                                          surface="cli", choice=approve, decided_by="user")
        rec.on_post_tool_call(tool_name=tool, args=args, result=result, duration_ms=40 + i * 7,
                              status="ok", **ids)
    rec.on_session_end(session_id=s, completed=True, interrupted=False, model="demo-model",
                       platform="cli")


def main() -> int:
    ap = argparse.ArgumentParser(prog="offline_ledger")
    cli.setup_argparse(ap)
    sub = [a for a in ap._subparsers._group_actions if isinstance(a, argparse._SubParsersAction)][0]
    sub.add_parser("simulate", help="record a simulated agent run")
    args = ap.parse_args()
    if args.ledger_command == "simulate":
        simulate(Path(args.dir or "."))
        return 0
    return cli.handle(args)


if __name__ == "__main__":
    raise SystemExit(main())
