"""Receipts: verifiable by a third party with only the public key, even when other
sessions' records sit in between (they appear as content-free stubs)."""

from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys

import pytest

from conftest import PLUGIN_DIR, core


@pytest.fixture
def interleaved(ledger):
    for i in range(3):
        ledger.append("tool_call", session="A", tool="terminal", args_redacted={"command": f"a{i}"})
        ledger.append("tool_call", session="B", tool="read_file", args_redacted={"path": "secret-b"})
        ledger.append("tool_result", session="A", tool="terminal", result_sha256=core.sha256_hex(str(i)))
    return ledger


def make_receipt(led, session="A"):
    return core.build_receipt(led.records(), session, led.keys, head=led.read_head())


def test_receipt_verifies_with_only_the_public_key(interleaved):
    receipt = json.loads(json.dumps(make_receipt(interleaved)))  # survives a JSON round trip
    res = core.verify_receipt(receipt, interleaved.keys.public_b64)
    assert res.ok, res.summary()
    assert res.count == 6
    assert receipt["summary"]["tools"] == {"terminal": 3}


def test_other_sessions_are_stubs_without_content(interleaved):
    receipt = make_receipt(interleaved)
    stubs = [e for e in receipt["entries"] if e.get("stub")]
    assert [s["seq"] for s in stubs] == [1, 4, 7]  # every B record inside A's range
    assert "secret-b" not in json.dumps(receipt)


def test_receipt_with_wrong_pinned_key_fails(interleaved):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = core.KeyPair(Ed25519PrivateKey.generate())
    res = core.verify_receipt(make_receipt(interleaved), other.public_b64)
    assert not res.ok


def test_without_pinned_key_it_verifies_but_warns(interleaved):
    res = core.verify_receipt(make_receipt(interleaved))
    assert res.ok and res.warnings


@pytest.mark.parametrize("mutate", [
    lambda r: r["entries"][0]["args_redacted"].update(command="evil"),   # edit
    lambda r: r["entries"].pop(2),                                        # delete
    lambda r: r["entries"].__setitem__(slice(1, 3), [r["entries"][2], r["entries"][1]]),  # reorder
], ids=["edit", "delete", "reorder"])
def test_tampered_receipt_fails(interleaved, mutate):
    receipt = make_receipt(interleaved)
    bad = copy.deepcopy(receipt)
    mutate(bad)
    res = core.verify_receipt(bad, interleaved.keys.public_b64)
    assert not res.ok


def test_tampered_entry_with_re_signed_envelope_still_fails(interleaved):
    """Even if an attacker could re-sign the outer receipt, the entry hashes and
    per-entry signatures still fail."""
    receipt = make_receipt(interleaved)
    receipt["entries"][0]["args_redacted"] = {"command": "evil"}
    unsigned = {k: v for k, v in receipt.items() if k != "receipt_sig"}
    receipt["receipt_sig"] = interleaved.keys.sign_hex(core.sha256_hex(core.canonical(unsigned)))
    res = core.verify_receipt(receipt, interleaved.keys.public_b64)
    assert not res.ok and res.broken_seq == 0


def test_standalone_verifier_needs_no_hermes(interleaved, tmp_path):
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(make_receipt(interleaved)))
    pub = tmp_path / "signer.pub"
    pub.write_text(interleaved.keys.public_b64)
    proc = subprocess.run([sys.executable, "-I", str(PLUGIN_DIR / "verify_receipt.py"), str(path),
                           "--pubkey", str(pub)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.startswith("OK:")
    data = json.loads(path.read_text())
    data["entries"][-1]["result_sha256"] = "0" * 64
    path.write_text(json.dumps(data))
    proc = subprocess.run([sys.executable, "-I", str(PLUGIN_DIR / "verify_receipt.py"), str(path),
                           "--pubkey", interleaved.keys.public_b64], capture_output=True, text=True)
    assert proc.returncode == 1 and proc.stdout.startswith("FAILED")


def test_public_key_accepts_base64_or_file(interleaved, tmp_path):
    raw = base64.b64decode(interleaved.keys.public_b64)
    assert core.key_id_for(core.public_raw(core.load_public_key(interleaved.keys.public_b64))) \
        == interleaved.keys.key_id
    f = tmp_path / "k.pub"
    f.write_text(interleaved.keys.public_b64 + "\n")
    assert core.public_raw(core.load_public_key(f)) == raw
