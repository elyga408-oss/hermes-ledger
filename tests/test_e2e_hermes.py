"""End to end against a real Hermes install and a temporary HERMES_HOME.

Skipped unless the `hermes` command is on PATH. The model-driven part also needs
HERMES_LEDGER_E2E_CHAT=1 and a configured model provider in the environment.

    HERMES_LEDGER_E2E_CHAT=1 python -m pytest tests/test_e2e_hermes.py -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import PLUGIN_DIR

HERMES = shutil.which("hermes")
pytestmark = pytest.mark.skipif(HERMES is None, reason="hermes is not installed")

COPY_IGNORE = shutil.ignore_patterns("tests", "demo", "__pycache__", ".pytest_cache", ".git")


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "hermes-home"
    (home / "plugins").mkdir(parents=True)
    shutil.copytree(PLUGIN_DIR, home / "plugins" / "hermes-ledger", ignore=COPY_IGNORE)
    return home


def hermes(home: Path, *argv: str, timeout: int = 180) -> subprocess.CompletedProcess:
    env = dict(os.environ, HERMES_HOME=str(home), NO_COLOR="1")
    return subprocess.run([HERMES, *argv], env=env, capture_output=True, text=True,
                          timeout=timeout)


def test_plugin_loads_and_is_listed(home):
    # `hermes plugins doctor` only exists in newer Hermes; 0.19 has `plugins list`.
    assert hermes(home, "plugins", "enable", "hermes-ledger").returncode == 0
    proc = hermes(home, "plugins", "list")
    assert proc.returncode == 0 and "hermes-ledger" in proc.stdout, proc.stdout + proc.stderr


def test_cli_round_trip_in_a_temp_home(home):
    assert hermes(home, "plugins", "enable", "hermes-ledger").returncode == 0
    proc = hermes(home, "ledger", "note", "e2e")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data_dir = home / "plugin-data" / "hermes-ledger"
    assert (data_dir / "ledger.jsonl").exists()
    ok = hermes(home, "ledger", "verify")
    assert ok.returncode == 0 and "OK: 1 records" in ok.stdout
    log = data_dir / "ledger.jsonl"
    original = log.read_bytes()
    log.write_bytes(original.replace(b"e2e", b"e3e"))
    bad = hermes(home, "ledger", "verify")
    assert bad.returncode == 1 and "BROKEN at seq 0" in bad.stdout
    log.write_bytes(original)
    assert hermes(home, "ledger", "verify").returncode == 0


@pytest.mark.skipif(os.environ.get("HERMES_LEDGER_E2E_CHAT") != "1",
                    reason="set HERMES_LEDGER_E2E_CHAT=1 (needs a model provider)")
def test_real_agent_run_is_recorded(home):
    # Model credentials live in the developer's own Hermes home; reuse its config and .env.
    src = Path(os.environ.get("HERMES_LEDGER_E2E_SOURCE_HOME", Path.home() / ".hermes"))
    for name in ("config.yaml", ".env", "auth.json"):
        if (src / name).exists():
            shutil.copy2(src / name, home / name)
    assert hermes(home, "plugins", "enable", "hermes-ledger").returncode == 0
    proc = hermes(home, "chat", "-q", "Use the terminal tool to run exactly: echo ledger-e2e",
                  "-Q", "-t", "terminal", timeout=600)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    shown = hermes(home, "ledger", "show", "--last", "0", "--json")
    recs = [json.loads(l) for l in shown.stdout.splitlines() if l.strip()]
    calls = [r for r in recs if r["kind"] == "tool_call" and r["tool"] == "terminal"]
    assert calls and "ledger-e2e" in json.dumps(calls[-1]["args_redacted"])
    assert any(r["kind"] == "tool_result" and r.get("call_seq") == calls[-1]["seq"] for r in recs)
    assert hermes(home, "ledger", "verify").returncode == 0
