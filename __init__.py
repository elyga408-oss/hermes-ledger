"""Hermes Ledger: a tamper-evident flight recorder for Hermes.

Every tool call (arguments redacted), its result hash, and every human approval
are appended to a local hash-chained, Ed25519-signed log. ``hermes ledger verify``
proves nothing was edited, deleted, reordered or truncated afterwards.
"""

from __future__ import annotations

import logging
from pathlib import Path

from . import cli
from .hooks import Recorder

logger = logging.getLogger("hermes_ledger")

HOOKS = (
    "pre_tool_call",
    "post_tool_call",
    "post_approval_response",
    "on_session_start",
    "on_session_end",
)

_recorder = Recorder()


def _cli_exit(args) -> int:
    """Hermes 0.19 ignores a handler's return value, so exit with it explicitly
    (verify must exit 1 on a broken chain for scripts and CI)."""
    code = cli.handle(args)
    if code:
        raise SystemExit(code)
    return code


def register(ctx) -> None:
    """Called once by Hermes at startup (documented plugin entry point)."""
    rec = _recorder
    ctx.register_hook("pre_tool_call", rec.on_pre_tool_call)
    ctx.register_hook("post_tool_call", rec.on_post_tool_call)
    ctx.register_hook("post_approval_response", rec.on_post_approval_response)
    ctx.register_hook("on_session_start", rec.on_session_start)
    ctx.register_hook("on_session_end", rec.on_session_end)

    ctx.register_cli_command(
        name="ledger",
        help="Verify, show and export the tamper-evident tool-call ledger",
        setup_fn=cli.setup_argparse,
        handler_fn=_cli_exit,
        description="hermes ledger verify | show | export --receipt | verify-receipt | key | note",
    )
    ctx.register_command(
        "ledger",
        cli.slash_command,
        description="Ledger status and recent entries (/ledger, /ledger verify, /ledger show 20)",
        args_hint="[verify|show N]",
    )

    skills_dir = Path(__file__).parent / "skills"
    if skills_dir.is_dir():
        for child in sorted(skills_dir.iterdir()):
            skill_md = child / "SKILL.md"
            if child.is_dir() and skill_md.exists():
                ctx.register_skill(child.name, skill_md)
