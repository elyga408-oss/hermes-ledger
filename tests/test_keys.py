"""Key handling: generated once, private file is 0600, never printed."""

from __future__ import annotations

import io
import os
import stat
import sys

import pytest

from conftest import cli_mod, core, fill


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_keypair_created_on_first_append_with_0600(ledger, ledger_dir):
    assert not (ledger_dir / core.PRIVATE_KEY_FILE).exists()
    fill(ledger, 1)
    mode = stat.S_IMODE(os.stat(ledger_dir / core.PRIVATE_KEY_FILE).st_mode)
    assert mode == 0o600
    assert stat.S_IMODE(os.stat(ledger_dir).st_mode) == 0o700


def test_key_is_stable_across_instances(ledger_dir):
    a = core.Ledger(ledger_dir).keys
    b = core.Ledger(ledger_dir).keys
    assert a.key_id == b.key_id and a.public_b64 == b.public_b64


def test_key_command_and_records_never_contain_private_key(ledger, ledger_dir):
    fill(ledger, 2)
    pem = (ledger_dir / core.PRIVATE_KEY_FILE).read_text()
    body = "".join(l for l in pem.splitlines() if not l.startswith("-----"))
    buf = io.StringIO()
    cli_mod.cmd_key(ledger, out=buf)
    cli_mod.cmd_show(ledger, last=0, out=buf)
    cli_mod.cmd_verify(ledger, out=buf)
    out = buf.getvalue()
    assert ledger.keys.public_b64 in out
    assert body not in out and "PRIVATE KEY" not in out
    assert body not in ledger.path.read_text()
    assert "key_id=" in repr(ledger.keys) and body not in repr(ledger.keys)
