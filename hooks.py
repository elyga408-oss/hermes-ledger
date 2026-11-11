"""Hermes hook callbacks that feed the ledger.

Every callback is fail-open: it catches its own exceptions, logs one warning per
distinct problem (then stays quiet at DEBUG), and returns ``None`` so it never
blocks, modifies or delays a tool call beyond one local append.
"""

from __future__ import annotations

import logging
import os
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Optional

try:  # loaded as a Hermes plugin package
    from . import ledger_core as core
    from .redact import redact, redact_string
except ImportError:  # loaded directly (tests, standalone tools)
    import ledger_core as core  # type: ignore[no-redef]
    from redact import redact, redact_string  # type: ignore[no-redef]

logger = logging.getLogger("hermes_ledger")

PLUGIN_NAME = "hermes-ledger"
_PENDING_MAX = 512


def default_ledger_dir() -> Path:
    """``<HERMES_HOME>/plugin-data/hermes-ledger/``, following the active profile."""
    try:
        from plugins.plugin_storage import plugin_data_dir  # documented Hermes helper
        return plugin_data_dir(PLUGIN_NAME)
    except Exception:
        home = os.environ.get("HERMES_HOME", "").strip()
        base = Path(home).expanduser() if home else Path.home() / ".hermes"
        return base / "plugin-data" / PLUGIN_NAME


class Recorder:
    """Turns hook payloads into ledger records. One per process."""

    def __init__(self, ledger_dir: Optional[Callable[[], Path] | Path] = None, *,
                 fsync: bool = True):
        self._dir_source = ledger_dir or default_ledger_dir
        self._fsync = fsync
        self._ledgers: dict[str, core.Ledger] = {}
        self._lock = threading.Lock()
        # tool_call_id -> seq of its tool_call record, and command digest -> seq (for approvals)
        self._pending_calls: "OrderedDict[str, int]" = OrderedDict()
        self._pending_cmds: "OrderedDict[str, int]" = OrderedDict()
        self._approvals: dict[int, int] = {}  # tool_call seq -> approval seq
        self._warned: set[str] = set()

    # -- plumbing
    def ledger(self) -> core.Ledger:
        d = self._dir_source() if callable(self._dir_source) else self._dir_source
        key = str(d)
        with self._lock:
            led = self._ledgers.get(key)
            if led is None:
                led = core.Ledger(Path(d), fsync=self._fsync)
                self._ledgers[key] = led
            return led

    def _warn(self, where: str, exc: BaseException) -> None:
        tag = f"{where}:{type(exc).__name__}"
        if tag in self._warned:
            logger.debug("hermes-ledger %s failed again: %s", where, exc)
            return
        self._warned.add(tag)
        logger.warning("hermes-ledger: %s failed (%s: %s); the agent continues, this event "
                       "is not recorded", where, type(exc).__name__, exc)

    def _remember(self, table: "OrderedDict[str, int]", key: str, seq: int) -> None:
        with self._lock:
            table[key] = seq
            table.move_to_end(key)
            while len(table) > _PENDING_MAX:
                table.popitem(last=False)

    def _safe(self, where: str, fn: Callable[[], Any]) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - fail open by contract
            self._warn(where, exc)
        return None

    @staticmethod
    def _session(kw: dict) -> str:
        return str(kw.get("session_id") or kw.get("task_id") or kw.get("session_key") or "")

    @staticmethod
    def _command_digest(command: Any) -> Optional[str]:
        if not isinstance(command, str) or not command:
            return None
        return core.sha256_hex(redact_string(command))

    # -- hooks
    def on_pre_tool_call(self, **kw: Any) -> None:
        return self._safe("pre_tool_call", lambda: self._pre_tool_call(kw))

    def _pre_tool_call(self, kw: dict) -> None:
        tool = str(kw.get("tool_name") or "")
        args = kw.get("args")
        full = redact(args, truncate=False)
        call_sha = core.sha256_hex(core.canonical({"tool": tool, "args": full}))
        shown = redact(args)
        extra: dict[str, Any] = {"call_sha256": call_sha}
        if shown != full:
            extra["args_truncated"] = True
        for k in ("tool_call_id", "turn_id"):
            if kw.get(k):
                extra[k] = str(kw[k])
        rec = self.ledger().append("tool_call", session=self._session(kw), tool=tool,
                                   args_redacted=shown, **extra)
        if kw.get("tool_call_id"):
            self._remember(self._pending_calls, str(kw["tool_call_id"]), rec["seq"])
        digest = self._command_digest(args.get("command") if isinstance(args, dict) else None)
        if digest:
            self._remember(self._pending_cmds, digest, rec["seq"])

    def on_post_tool_call(self, **kw: Any) -> None:
        return self._safe("post_tool_call", lambda: self._post_tool_call(kw))

    def _post_tool_call(self, kw: dict) -> None:
        tool = str(kw.get("tool_name") or "")
        result = kw.get("result")
        if isinstance(result, str):
            result_bytes = result.encode("utf-8", "replace")
        else:
            result_bytes = core.canonical(result)
        extra: dict[str, Any] = {"result_len": len(result_bytes)}
        if kw.get("status"):
            extra["status"] = str(kw["status"])
        if isinstance(kw.get("duration_ms"), (int, float)):
            extra["duration_ms"] = int(kw["duration_ms"])
        if kw.get("error_type"):
            extra["error_type"] = str(kw["error_type"])
        call_id = str(kw.get("tool_call_id") or "")
        if call_id:
            extra["tool_call_id"] = call_id
        with self._lock:
            call_seq = self._pending_calls.pop(call_id, None) if call_id else None
            approval_seq = self._approvals.pop(call_seq, None) if call_seq is not None else None
        if call_seq is not None:
            extra["call_seq"] = call_seq
        if approval_seq is not None:
            extra["approval_seq"] = approval_seq
        self.ledger().append("tool_result", session=self._session(kw), tool=tool,
                             args_redacted=None, result_sha256=core.sha256_hex(result_bytes),
                             **extra)

    def on_post_approval_response(self, **kw: Any) -> None:
        return self._safe("post_approval_response", lambda: self._approval(kw))

    def _approval(self, kw: dict) -> None:
        command = kw.get("command")
        digest = self._command_digest(command)
        with self._lock:
            binds = self._pending_cmds.get(digest) if digest else None
        approval = {
            "choice": str(kw.get("choice") or ""),
            "surface": str(kw.get("surface") or ""),
            "decided_by": kw.get("decided_by") if isinstance(kw.get("decided_by"), str) else None,
            "pattern_key": kw.get("pattern_key") if isinstance(kw.get("pattern_key"), str) else None,
            "description": redact(kw.get("description")) if kw.get("description") else None,
            "command_sha256": digest,
            "binds_seq": binds,
        }
        rec = self.ledger().append("approval", session=self._session(kw), tool=None,
                                   args_redacted={"command": redact(command)} if command else None,
                                   approval=approval)
        if binds is not None:
            with self._lock:
                self._approvals[binds] = rec["seq"]

    def on_session_start(self, **kw: Any) -> None:
        return self._safe("on_session_start", lambda: self._note(kw, "session started"))

    def on_session_end(self, **kw: Any) -> None:
        return self._safe("on_session_end", lambda: self._note(kw, "session turn ended"))

    def _note(self, kw: dict, text: str) -> None:
        meta = {k: kw[k] for k in ("model", "platform", "completed", "interrupted")
                if isinstance(kw.get(k), (str, bool))}
        self.ledger().append("note", session=self._session(kw), tool=None,
                             args_redacted=meta or None, note=text)


def bind_check(records: list[dict]) -> list[str]:
    """Problems with approval binding: an approval naming a call it does not match."""
    by_seq = {r.get("seq"): r for r in records}
    problems = []
    for r in records:
        if r.get("kind") != "approval":
            continue
        appr = r.get("approval") or {}
        target = appr.get("binds_seq")
        if target is None:
            continue
        call = by_seq.get(target)
        if call is None or call.get("kind") != "tool_call" or target >= r["seq"]:
            problems.append(f"approval seq {r['seq']} binds seq {target}, which is not an earlier "
                            "tool call")
            continue
        args = call.get("args_redacted") if isinstance(call.get("args_redacted"), dict) else {}
        cmd = args.get("command")
        if not call.get("args_truncated") and isinstance(cmd, str) \
                and core.sha256_hex(cmd) != appr.get("command_sha256"):
            problems.append(f"approval seq {r['seq']} does not match the command of tool call "
                            f"seq {target}")
    for r in records:
        if r.get("kind") == "tool_result" and r.get("approval_seq") is not None:
            a = by_seq.get(r["approval_seq"])
            if a is None or a.get("kind") != "approval" or \
                    (a.get("approval") or {}).get("binds_seq") != r.get("call_seq"):
                problems.append(f"tool result seq {r['seq']} cites approval seq "
                                f"{r['approval_seq']}, which does not name its call")
    return problems
