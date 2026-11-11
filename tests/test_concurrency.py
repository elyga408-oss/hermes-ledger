"""Two writers (threads or processes) never fork the chain."""

from __future__ import annotations

import multiprocessing as mp
import threading

from conftest import PLUGIN_DIR, core


def _proc_writer(directory: str, tag: str, n: int) -> None:
    import sys
    sys.path.insert(0, str(PLUGIN_DIR))
    import ledger_core
    led = ledger_core.Ledger(directory)
    for i in range(n):
        led.append("tool_call", session=tag, tool="t", args_redacted={"i": i})


def test_threads_do_not_fork_the_chain(ledger):
    ledger.append("note", session="x", note="start")  # create the key first
    threads = [threading.Thread(target=lambda t=t: [ledger.append(
        "tool_call", session=t, tool="t", args_redacted={"i": i}) for i in range(40)])
        for t in ("a", "b", "c")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    res = ledger.verify()
    assert res.ok, res.summary()
    assert res.count == 121
    recs = ledger.records()
    assert len({r["seq"] for r in recs}) == len(recs) == 121


def test_processes_do_not_fork_the_chain(ledger_dir):
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_proc_writer, args=(str(ledger_dir), tag, 30))
             for tag in ("p1", "p2")]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    led = core.Ledger(ledger_dir)
    res = led.verify()
    assert res.ok, res.summary()
    assert res.count == 60
    recs = led.records()
    assert sorted(r["seq"] for r in recs) == list(range(60))
    assert {r["key_id"] for r in recs} == {led.keys.key_id}  # one key, even when both raced to create it
