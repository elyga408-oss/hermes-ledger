"""Behaviour contracts of the chain: a verified log is exactly the appended one,
and every kind of after-the-fact change is reported at the first affected seq."""

from __future__ import annotations

import json

from conftest import core, fill


def lines_of(led):
    return led.path.read_bytes().splitlines(keepends=True)


def write_lines(led, lines):
    led.path.write_bytes(b"".join(lines))


def test_untouched_log_verifies_with_count_and_head(filled):
    res = filled.verify()
    assert res.ok, res.summary()
    assert res.count == 6
    assert res.last_hash == filled.records()[-1]["hash"]
    assert res.summary().startswith("OK: 6 records")


def test_records_are_canonical_json_lines_with_required_fields(filled):
    for raw in lines_of(filled):
        rec = json.loads(raw)
        assert raw.rstrip(b"\n") == core.canonical(rec)
        for f in ("seq", "ts", "session", "kind", "tool", "args_redacted", "result_sha256",
                  "prev_hash", "hash", "sig"):
            assert f in rec
    recs = filled.records()
    assert [r["seq"] for r in recs] == list(range(6))
    assert recs[0]["prev_hash"] == core.GENESIS_HASH
    assert all(b["prev_hash"] == a["hash"] for a, b in zip(recs, recs[1:]))


def test_edit_one_byte_fails_at_that_seq(filled):
    lines = lines_of(filled)
    lines[3] = lines[3].replace(b"echo 3", b"echo 9")
    write_lines(filled, lines)
    res = filled.verify()
    assert not res.ok and res.broken_seq == 3
    assert "edited" in res.reason


def test_edit_that_breaks_json_fails_at_that_seq(filled):
    lines = lines_of(filled)
    lines[2] = lines[2][:10] + b"#" + lines[2][11:]
    write_lines(filled, lines)
    res = filled.verify()
    assert not res.ok and res.broken_seq == 2


def test_edit_with_recomputed_hash_but_no_key_fails_on_signature(filled):
    lines = lines_of(filled)
    rec = json.loads(lines[4])
    rec["args_redacted"] = {"command": "something else"}
    rec["hash"] = core.record_hash(rec)
    lines[4] = core.canonical(rec) + b"\n"
    write_lines(filled, lines)
    res = filled.verify()
    assert not res.ok and res.broken_seq == 4
    assert "signature" in res.reason


def test_delete_middle_record_fails_at_missing_seq(filled):
    lines = lines_of(filled)
    del lines[2]
    write_lines(filled, lines)
    res = filled.verify()
    assert not res.ok and res.broken_seq == 2
    assert "missing" in res.reason


def test_reorder_fails_at_first_out_of_place_seq(filled):
    lines = lines_of(filled)
    lines[1], lines[2] = lines[2], lines[1]
    write_lines(filled, lines)
    res = filled.verify()
    assert not res.ok and res.broken_seq == 1


def test_truncate_newest_records_is_caught_by_signed_head(filled):
    lines = lines_of(filled)
    write_lines(filled, lines[:4])
    res = filled.verify()
    assert not res.ok and res.broken_seq == 4
    assert "truncated" in res.reason


def test_torn_partial_last_line_fails_at_that_seq(filled):
    data = filled.path.read_bytes()
    filled.path.write_bytes(data[:-40])
    res = filled.verify()
    assert not res.ok and res.broken_seq == 5


def test_swapped_key_fails_at_seq_zero(filled, ledger_dir):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other = core.KeyPair(Ed25519PrivateKey.generate())
    (ledger_dir / core.PUBLIC_KEY_FILE).write_text(other.public_b64 + "\n")
    res = filled.verify()
    assert not res.ok and res.broken_seq == 0
    assert "key" in res.reason


def test_pinned_pubkey_detects_full_rewrite_with_new_key(filled, ledger_dir):
    pinned = filled.keys.public_b64
    # attacker deletes everything and rebuilds a plausible log with a fresh key
    for name in (core.LEDGER_FILE, core.HEAD_FILE, core.PRIVATE_KEY_FILE, core.PUBLIC_KEY_FILE):
        (ledger_dir / name).unlink()
    forged = core.Ledger(ledger_dir)
    fill(forged)
    assert forged.verify().ok  # self-consistent...
    res = forged.verify(pinned)  # ...but not under the key we pinned
    assert not res.ok and res.broken_seq == 0


def test_restoring_the_original_bytes_turns_verify_green_again(filled):
    original = filled.path.read_bytes()
    filled.path.write_bytes(original.replace(b"echo 2", b"echo X"))
    assert not filled.verify().ok
    filled.path.write_bytes(original)
    assert filled.verify().ok


def test_appending_after_reopen_continues_the_chain(ledger_dir):
    a = core.Ledger(ledger_dir)
    fill(a, 3)
    b = core.Ledger(ledger_dir)  # fresh process view: same key, continues seq
    rec = b.append("note", session="s1", note="later")
    assert rec["seq"] == 3
    assert b.verify().ok and b.verify().count == 4


def test_empty_ledger_is_ok(ledger):
    res = ledger.verify()
    assert res.ok and res.count == 0


def test_unknown_kind_is_rejected(ledger):
    import pytest
    with pytest.raises(ValueError):
        ledger.append("bogus")
