#!/usr/bin/env bash
# Terminal part of the Hermes Ledger demo (see DEMO.md for the shot list).
#
#   demo/run_demo.sh            real run: Hermes does a tiny task, then we tamper and verify
#   demo/run_demo.sh --offline  no Hermes or model needed: a simulated run in a temp folder
#
# Never touches anything but the ledger it creates or the one in $HERMES_HOME, and it
# restores the one byte it changes.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAUSE="${DEMO_PAUSE:-1.5}"
step() { printf '\n\033[1;36m$ %s\033[0m\n' "$*"; sleep "$PAUSE"; }

if [[ "${1:-}" == "--offline" ]]; then
  DIR="$(mktemp -d)/ledger"
  LEDGER=(python3 "$HERE/offline_ledger.py" --dir "$DIR")
  step "hermes chat -q 'tidy my notes folder'   # (simulated agent run)"
  "${LEDGER[@]}" simulate
else
  : "${HERMES_HOME:=$HOME/.hermes}"
  DIR="$HERMES_HOME/plugin-data/hermes-ledger"
  LEDGER=(hermes ledger)
  step "hermes chat -q 'How many files are in this folder? Use the terminal.' -Q -t terminal"
  hermes chat -q "How many files are in this folder? Use the terminal." -Q -t terminal
fi
LOG="$DIR/ledger.jsonl"

step "hermes ledger show --last 8"
"${LEDGER[@]}" show --last 8

step "hermes ledger verify"
"${LEDGER[@]}" verify

# Pick the newest tool_call that ran a command, and change one byte of that command.
TARGET="$(python3 - "$LOG" <<'PY'
import json, sys
lines = open(sys.argv[1], "rb").read().splitlines()
for i in range(len(lines) - 1, -1, -1):
    rec = json.loads(lines[i])
    if rec.get("kind") == "tool_call" and "command" in (rec.get("args_redacted") or {}):
        print(i, rec["seq"]); break
PY
)"
read -r LINE SEQ <<<"$TARGET"
cp "$LOG" "$LOG.demo-backup"
step "# an attacker edits ONE byte of entry #$SEQ"
python3 - "$LOG" "$LINE" <<'PY'
import sys
path, line = sys.argv[1], int(sys.argv[2])
lines = open(path, "rb").read().split(b"\n")
raw = lines[line]
pos = raw.index(b'"command":"') + len(b'"command":"')
while not chr(raw[pos]).isalpha():
    pos += 1
before = raw[pos:pos + 1]
after = before.swapcase()
lines[line] = raw[:pos] + after + raw[pos + 1:]
open(path, "wb").write(b"\n".join(lines))
print(f"   in the recorded command, {before.decode()!r} becomes {after.decode()!r}")
PY

step "hermes ledger verify"
"${LEDGER[@]}" verify || true

step "# restore the original byte"
mv "$LOG.demo-backup" "$LOG"

step "hermes ledger verify"
"${LEDGER[@]}" verify

step "hermes ledger export --receipt --out receipt.json   # proof for someone else"
RECEIPT="$(mktemp -d)/receipt.json"
"${LEDGER[@]}" export --receipt --out "$RECEIPT"
PUB="$("${LEDGER[@]}" key | awk '/public key:/ {print $3}')"
step "python3 verify_receipt.py receipt.json --pubkey <their public key>"
python3 -I "$HERE/../verify_receipt.py" "$RECEIPT" --pubkey "$PUB"
