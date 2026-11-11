"""Dashboard routes for hermes-ledger, mounted at /api/plugins/hermes-ledger/.

Read-only: verifies the chain and returns recent records. Never returns key material.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from pathlib import Path

from fastapi import APIRouter

_CORE_NAME = "hermes_ledger_dashboard_core"


def _core():
    mod = sys.modules.get(_CORE_NAME)
    if mod is None:
        path = Path(__file__).resolve().parent.parent / "ledger_core.py"
        spec = importlib.util.spec_from_file_location(_CORE_NAME, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_CORE_NAME] = mod
        spec.loader.exec_module(mod)
    return mod


def _ledger_dir() -> Path:
    try:
        from plugins.plugin_storage import plugin_data_dir
        return plugin_data_dir("hermes-ledger")
    except Exception:
        home = os.environ.get("HERMES_HOME", "").strip()
        base = Path(home).expanduser() if home else Path.home() / ".hermes"
        return base / "plugin-data" / "hermes-ledger"


def _status(last: int) -> dict:
    core = _core()
    led = core.Ledger(_ledger_dir())
    result = led.verify().to_dict()
    records = led.records()
    last = max(1, min(int(last), 500))
    return {"verify": result, "records": records[-last:], "total": len(records)}


router = APIRouter()


@router.get("/status")
async def status(last: int = 100):
    return await asyncio.to_thread(_status, last)
