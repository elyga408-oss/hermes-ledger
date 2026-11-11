#!/usr/bin/env python3
"""Verify a Hermes Ledger receipt without Hermes.

Needs only Python 3.11+ and the ``cryptography`` package::

    python verify_receipt.py receipt.json --pubkey <base64 public key or key file>

Exit status 0 means the receipt is intact and signed by that key.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ledger_core  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("receipt")
    ap.add_argument("--pubkey", help="the signer's public key, obtained separately (recommended)")
    args = ap.parse_args(argv)
    receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    res = ledger_core.verify_receipt(receipt, args.pubkey)
    print(("OK: " if res.ok else "FAILED: ") + (
        f"session {receipt.get('session')}, {res.count} records, key {res.key_id}"
        if res.ok else res.summary()))
    for w in res.warnings:
        print(f"note: {w}")
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
