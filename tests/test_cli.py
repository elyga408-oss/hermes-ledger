"""The `hermes ledger` argparse tree, driven the way Hermes's main() drives it:
parse, then args.func(args), whose int return is the exit code."""

from __future__ import annotations

import argparse
import io
import json

import pytest

from conftest import FakeCtx, cli_mod, core, fill, plugin


@pytest.fixture
def hermes(ledger_dir, monkeypatch, capsys):
    ctx = FakeCtx()
    plugin.register(ctx)
    info = ctx.cli["ledger"]
    top = argparse.ArgumentParser(prog="hermes")
    subs = top.add_subparsers(dest="command")
    p = subs.add_parser("ledger", help=info["help"])
    info["setup_fn"](p)
    p.set_defaults(func=info["handler_fn"])

    def run(*argv):
        args = top.parse_args(["ledger", "--dir", str(ledger_dir), *argv])
        try:
            rc = args.func(args)
        except SystemExit as e:  # the real CLI exits non-zero on failure
            rc = e.code
        out = capsys.readouterr().out
        return rc, out
    return run


def test_verify_green_then_red_then_green(hermes, ledger):
    fill(ledger, 5)
    rc, out = hermes("verify")
    assert rc == 0 and "OK: 5 records" in out
    original = ledger.path.read_bytes()
    ledger.path.write_bytes(original.replace(b"echo 3", b"echo 7"))
    rc, out = hermes("verify")
    assert rc == 1 and "BROKEN at seq 3" in out
    ledger.path.write_bytes(original)
    rc, out = hermes("verify")
    assert rc == 0


def test_verify_json(hermes, ledger):
    fill(ledger, 2)
    rc, out = hermes("verify", "--json")
    data = json.loads(out)
    assert rc == 0 and data["ok"] and data["count"] == 2


def test_show_filters(hermes, ledger):
    fill(ledger, 3)
    ledger.append("tool_call", session="s1", tool="read_file", args_redacted={"path": "a.md"})
    rc, out = hermes("show", "--tool", "read_file")
    assert rc == 0 and "read_file" in out and "echo" not in out
    rc, out = hermes("show", "--last", "2", "--json")
    assert [json.loads(l)["seq"] for l in out.splitlines()] == [2, 3]


def test_export_and_verify_receipt(hermes, ledger, tmp_path):
    fill(ledger, 3, session="sess-x")
    out_file = tmp_path / "r.json"
    rc, out = hermes("export", "--receipt", "--out", str(out_file))
    assert rc == 0 and "sess-x" in out
    rc, out = hermes("verify-receipt", str(out_file), "--pubkey", ledger.keys.public_b64)
    assert rc == 0 and "receipt valid" in out


def test_export_refuses_a_broken_ledger(hermes, ledger, tmp_path):
    fill(ledger, 3)
    ledger.path.write_bytes(ledger.path.read_bytes().replace(b"echo 1", b"echo 8"))
    rc, _ = hermes("export", "--receipt", "--out", str(tmp_path / "r.json"))
    assert rc == 1 and not (tmp_path / "r.json").exists()


def test_note_and_key(hermes, ledger):
    rc, out = hermes("note", "demo", "starts")
    assert rc == 0 and "seq 0" in out
    rc, out = hermes("key")
    assert ledger.keys.public_b64 in out


def test_slash_command(ledger, ledger_dir):
    fill(ledger, 4)
    text = cli_mod.slash_command("", ledger_dir=lambda: ledger_dir)
    assert text.startswith("✔ OK: 4 records") and "terminal" in text
    assert cli_mod.slash_command("verify", ledger_dir=lambda: ledger_dir).startswith("✔")


def test_default_dir_follows_hermes_home(hermes_home):
    from conftest import hooks_mod
    assert hooks_mod.default_ledger_dir() == hermes_home / "plugin-data" / "hermes-ledger"
