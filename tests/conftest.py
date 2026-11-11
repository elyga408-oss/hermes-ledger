"""Shared fixtures. The plugin directory is imported as a package, the way Hermes
loads it, so relative imports inside the plugin are exercised. There is no
tests/__init__.py on purpose (a test package must not shadow the plugin)."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent
PKG = "hermes_ledger_under_test"


def load_plugin():
    if PKG in sys.modules:
        return sys.modules[PKG]
    spec = importlib.util.spec_from_file_location(
        PKG, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[PKG] = mod
    spec.loader.exec_module(mod)
    return mod


plugin = load_plugin()
core = sys.modules[f"{PKG}.ledger_core"]
hooks_mod = sys.modules[f"{PKG}.hooks"]
cli_mod = sys.modules[f"{PKG}.cli"]
redact_mod = sys.modules[f"{PKG}.redact"]


class FakeCtx:
    """Records registrations using the documented PluginContext signatures, and
    dispatches hooks the way Hermes does: keyword payloads, callback errors are
    caught and logged (fail-open)."""

    def __init__(self):
        self.hooks: dict[str, list] = {}
        self.cli: dict[str, dict] = {}
        self.commands: dict[str, dict] = {}
        self.skills: dict[str, Path] = {}

    def register_hook(self, hook_name, callback, *, hold_stream=False):
        self.hooks.setdefault(hook_name, []).append(callback)

    def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
        self.cli[name] = {"help": help, "setup_fn": setup_fn, "handler_fn": handler_fn,
                          "description": description}

    def register_command(self, name, handler, description="", args_hint="", argument_mode=None):
        self.commands[name] = {"handler": handler, "description": description}

    def register_skill(self, name, path, *args, **kwargs):
        self.skills[name] = Path(path)

    def invoke(self, hook_name, **payload):
        payload.setdefault("telemetry_schema_version", "hermes.observer.v1")
        results = []
        for cb in self.hooks.get(hook_name, []):
            try:
                results.append(cb(**payload))
            except Exception:  # Hermes logs and skips a crashing callback
                logging.getLogger("fake-hermes").exception("hook crashed")
                results.append("CRASHED")
        return results


@pytest.fixture
def hermes_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


@pytest.fixture
def ledger_dir(hermes_home):
    return hermes_home / "plugin-data" / "hermes-ledger"


@pytest.fixture
def ledger(ledger_dir):
    return core.Ledger(ledger_dir)


def fill(led, n=6, session="s1"):
    out = []
    for i in range(n):
        out.append(led.append("tool_call", session=session, tool="terminal",
                              args_redacted={"command": f"echo {i}"}))
    return out


@pytest.fixture
def filled(ledger):
    fill(ledger)
    return ledger
