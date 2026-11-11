"""The plugin as Hermes sees it: registration, a simulated run, approval binding,
and the fail-open contract (a broken ledger never breaks the agent)."""

from __future__ import annotations

import logging
import time

import pytest

from conftest import PLUGIN_DIR, FakeCtx, core, hooks_mod, plugin


@pytest.fixture
def ctx_and_recorder(ledger_dir, monkeypatch):
    rec = hooks_mod.Recorder(ledger_dir)
    monkeypatch.setattr(plugin, "_recorder", rec)
    ctx = FakeCtx()
    plugin.register(ctx)
    return ctx, rec


def run_tool(ctx, tool, args, call_id, result='{"ok": true}', session="sess-1", approve=None):
    ctx.invoke("pre_tool_call", tool_name=tool, args=args, task_id=session, session_id=session,
               tool_call_id=call_id, turn_id="turn-1", api_request_id="r1")
    if approve:
        ctx.invoke("pre_approval_request", command=args.get("command"), description="danger",
                   pattern_key="rm", pattern_keys=["rm"], session_key=session, surface="cli")
        ctx.invoke("post_approval_response", command=args.get("command"), description="danger",
                   pattern_key="rm", pattern_keys=["rm"], session_key=session, surface="cli",
                   choice=approve, decided_by="user")
    ctx.invoke("post_tool_call", tool_name=tool, args=args, result=result, task_id=session,
               session_id=session, tool_call_id=call_id, turn_id="turn-1", api_request_id="r1",
               duration_ms=12, status="ok", error_type=None, error_message=None)


def test_registration_matches_manifest(ctx_and_recorder):
    ctx, _ = ctx_and_recorder
    text = (PLUGIN_DIR / "plugin.yaml").read_text()
    declared = [l.strip()[2:] for l in text.split("provides_hooks:")[1].splitlines()
                if l.strip().startswith("- ")]
    assert sorted(declared) == sorted(ctx.hooks)
    assert "ledger" in ctx.cli and "ledger" in ctx.commands
    assert "ledger-audit" in ctx.skills and ctx.skills["ledger-audit"].exists()
    assert all(cb.__code__.co_flags & 0x08 for cbs in ctx.hooks.values() for cb in cbs), \
        "every hook callback accepts **kwargs"


def test_simulated_run_produces_a_linked_verifiable_timeline(ctx_and_recorder, ledger_dir):
    ctx, _ = ctx_and_recorder
    ctx.invoke("on_session_start", session_id="sess-1", model="m", platform="cli")
    run_tool(ctx, "read_file", {"path": "README.md"}, "c1", result="hello")
    run_tool(ctx, "terminal", {"command": "ls"}, "c2", result='{"output": "a b"}')
    ctx.invoke("on_session_end", session_id="sess-1", completed=True, interrupted=False,
               model="m", platform="cli")
    led = core.Ledger(ledger_dir)
    recs = led.records()
    assert [r["kind"] for r in recs] == ["note", "tool_call", "tool_result", "tool_call",
                                        "tool_result", "note"]
    assert recs[2]["call_seq"] == recs[1]["seq"] and recs[4]["call_seq"] == recs[3]["seq"]
    assert recs[2]["result_sha256"] == core.sha256_hex("hello")
    assert recs[2]["status"] == "ok" and recs[2]["duration_ms"] == 12
    assert led.verify().ok


def test_hooks_return_none_so_they_never_block_or_modify(ctx_and_recorder):
    ctx, _ = ctx_and_recorder
    results = ctx.invoke("pre_tool_call", tool_name="terminal", args={"command": "ls"},
                         session_id="s", tool_call_id="x")
    assert results == [None]


def test_approval_binds_to_the_exact_call(ctx_and_recorder, ledger_dir):
    ctx, _ = ctx_and_recorder
    run_tool(ctx, "terminal", {"command": "rm -r build"}, "c9", approve="once")
    recs = core.Ledger(ledger_dir).records()
    call, approval, result = recs
    assert approval["kind"] == "approval"
    assert approval["approval"]["binds_seq"] == call["seq"]
    assert approval["approval"]["choice"] == "once"
    assert result["approval_seq"] == approval["seq"] and result["call_seq"] == call["seq"]
    assert hooks_mod.bind_check(recs) == []


def test_approval_for_a_different_command_does_not_bind(ctx_and_recorder, ledger_dir):
    ctx, _ = ctx_and_recorder
    ctx.invoke("pre_tool_call", tool_name="terminal", args={"command": "ls"},
               session_id="s", tool_call_id="c1")
    ctx.invoke("post_approval_response", command="rm -r /data", surface="cli", choice="once",
               session_key="s")
    recs = core.Ledger(ledger_dir).records()
    assert recs[1]["approval"]["binds_seq"] is None


def test_bind_check_flags_an_approval_that_names_the_wrong_call(ctx_and_recorder, ledger_dir):
    ctx, _ = ctx_and_recorder
    run_tool(ctx, "terminal", {"command": "rm -r build"}, "c9", approve="once")
    recs = core.Ledger(ledger_dir).records()
    recs[1]["approval"]["command_sha256"] = core.sha256_hex("something else")
    assert hooks_mod.bind_check(recs)


def test_hook_errors_never_break_the_run(tmp_path, monkeypatch, caplog):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x")  # the ledger dir path is a file: every append fails
    rec = hooks_mod.Recorder(blocker / "ledger")
    monkeypatch.setattr(plugin, "_recorder", rec)
    ctx = FakeCtx()
    plugin.register(ctx)
    with caplog.at_level(logging.WARNING, logger="hermes_ledger"):
        for i in range(5):
            out = []
            out += ctx.invoke("pre_tool_call", tool_name="terminal", args={"command": "ls"},
                              session_id="s", tool_call_id=f"c{i}")
            out += ctx.invoke("post_tool_call", tool_name="terminal", args={}, result="r",
                              session_id="s", tool_call_id=f"c{i}", duration_ms=1, status="ok")
            out += ctx.invoke("post_approval_response", command="ls", choice="once")
            assert "CRASHED" not in out and out == [None, None, None]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "a failure is reported"
    assert len(warnings) <= 3, "one warning per distinct failure, not one per call"


def test_odd_payloads_do_not_crash(ctx_and_recorder, ledger_dir):
    ctx, _ = ctx_and_recorder

    class Weird:
        def __repr__(self):
            return "<weird token=abc>"

    out = ctx.invoke("pre_tool_call", tool_name=None, args=[1, Weird(), b"bytes"])
    out += ctx.invoke("post_tool_call", tool_name="x", result={"not": "a string"})
    out += ctx.invoke("post_approval_response")
    out += ctx.invoke("on_session_start")
    assert out == [None, None, None, None]
    assert core.Ledger(ledger_dir).verify().ok


def test_append_cost_is_small(ledger_dir):
    rec = hooks_mod.Recorder(ledger_dir)
    start = time.perf_counter()
    for i in range(50):
        rec.on_pre_tool_call(tool_name="t", args={"i": i}, session_id="s", tool_call_id=str(i))
    per_call_ms = (time.perf_counter() - start) * 1000 / 50
    assert per_call_ms < 50, f"{per_call_ms:.1f} ms per recorded call"
