"""Redaction contract: sensitive keys and token-shaped values never reach the log."""

from __future__ import annotations

from conftest import FakeCtx, hooks_mod, plugin, redact_mod

redact = redact_mod.redact
MASK = redact_mod.MASK

# Built at runtime so the repository never contains a token-shaped literal.
SK = "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
GH = "ghp" + "_" + "x" * 36
BEARER_TOKEN = "abc." + "D" * 24


def test_values_under_sensitive_keys_are_masked_at_any_depth():
    out = redact({"api_key": "v1", "headers": {"Authorization": "x", "Cookie": "c"},
                  "nested": [{"client_secret": "s", "Password": "p", "token": 3}],
                  "path": "/tmp/a"})
    assert out["api_key"] == MASK
    assert out["headers"] == {"Authorization": MASK, "Cookie": MASK}
    assert out["nested"][0] == {"client_secret": MASK, "Password": MASK, "token": MASK}
    assert out["path"] == "/tmp/a"


def test_token_shaped_values_are_masked_inside_strings():
    cmd = (f"curl -H 'Authorization: Bearer {BEARER_TOKEN}' https://x "
           f"&& OPENAI_API_KEY={SK} run --token {GH} https://user:pw123@host/p")
    out = redact({"command": cmd})["command"]
    for secret in (SK, GH, BEARER_TOKEN, "pw123"):
        assert secret not in out
    assert "https://x" in out and "run" in out


def test_plain_arguments_are_left_alone():
    args = {"command": "ls -la /srv", "path": "notes.md", "limit": 5, "flag": True}
    assert redact(args) == args


def test_long_strings_are_truncated_but_hash_uses_full_redacted_args():
    out = redact({"content": "a" * 10000})
    assert len(out["content"]) < 5000 and "+" in out["content"]
    assert len(redact({"content": "a" * 10000}, truncate=False)["content"]) == 10000


def test_hook_writes_redacted_args_only(ledger):
    rec = hooks_mod.Recorder(ledger.dir, fsync=False)
    ctx = FakeCtx()
    plugin._recorder, saved = rec, plugin._recorder
    try:
        plugin.register(ctx)
    finally:
        plugin._recorder = saved
    ctx.invoke("pre_tool_call", tool_name="terminal",
               args={"command": f"export ANTHROPIC_API_KEY={SK}", "auth_header": "Bearer zzz"},
               task_id="t", session_id="s", tool_call_id="c1")
    text = ledger.path.read_text()
    assert SK not in text and "zzz" not in text
    assert MASK in text
