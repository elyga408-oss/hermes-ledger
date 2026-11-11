# Hermes Ledger

**A tamper-evident flight recorder for Hermes Agent.**

Agents act on your behalf: they run commands, edit files and call APIs. When you ask afterwards "what did my agent actually do?", you need evidence, not the agent's memory of it. Hermes Ledger records every tool call (arguments redacted), a SHA-256 of every result, and every human approval in a local log. Each record is hash-chained to the one before it and signed with an Ed25519 key. One command checks the whole log:

```
$ hermes ledger verify
✔ OK: 11 records, chain intact, head 12461d2575be, key 75ec9a7750155b04

$ hermes ledger verify        # after someone changed one byte of entry 5
✘ BROKEN at seq 5 (line 6): content does not match its hash: record was edited
```

A prompt or a skill can describe what happened. It cannot make the record of it tamper-evident. This plugin can.

## What it records

| kind | when | what is stored |
|---|---|---|
| `tool_call` | `pre_tool_call` hook | tool name, redacted arguments, a digest of the call, tool-call and turn ids |
| `tool_result` | `post_tool_call` hook | SHA-256 and length of the result (not the result), status, duration, link to its call |
| `approval` | `post_approval_response` hook | the choice (`once`, `session`, `always`, `deny`, `timeout`...), surface, redacted command, and the call it **binds** to |
| `note` | session start and end, `hermes ledger note` | model, platform, completion flags, free text |

**Approval binding.** An approval record names the exact pending call it approved (`binds_seq`, matched on the digest of the redacted command), and that call's result cites the approval (`approval_seq`). `hermes ledger verify` reports any approval that names a call it does not match, so an approval for one command cannot be passed off as approval for another.

**Redaction.** Values under keys matching `(?i)(key|token|secret|password|passwd|auth|cookie|credential)` are replaced with `[REDACTED]`, at any depth. Inside strings, `Bearer ...`, `sk-...` keys, GitHub/Slack/AWS/Google token shapes, JWTs, PEM private keys, URL passwords and `NAME=value` assignments with a sensitive name are masked. Long strings are cut to 4,000 characters (the call digest still covers the full redacted arguments). Redaction is pattern-based, so it is best effort: see the threat model.

**It never gets in the agent's way.** Every hook catches its own errors, logs one warning per distinct problem, and returns nothing, so it cannot block, change or retry a tool call. An append takes a file lock, one `O_APPEND` write and an `fsync`: a few milliseconds.

## Install

Requires Hermes `>=0.19.0` (tested on 0.19.0, the current PyPI release). The only dependency is `cryptography` (already part of Hermes).

```bash
hermes plugins install https://github.com/elyga408-oss/hermes-ledger
hermes plugins enable hermes-ledger
```

Or from a local checkout: copy this folder to `~/.hermes/plugins/hermes-ledger/` and run `hermes plugins enable hermes-ledger`. Check it loads with `hermes plugins doctor ~/.hermes/plugins/hermes-ledger --ci`.

On first use the plugin creates its data directory, `<HERMES_HOME>/plugin-data/hermes-ledger/` (mode `0700`):

| file | contents |
|---|---|
| `ledger.jsonl` | the log, one canonical JSON record per line |
| `ledger.head` | signed pointer to the newest record (detects truncation) |
| `ed25519.key` | private signing key, PKCS#8 PEM, mode `0600`, never printed or logged |
| `ed25519.pub` | public key, base64 |

## The three commands

```bash
hermes ledger verify [--pubkey KEY] [--json]
```
Walks the chain from the first record. Prints `OK: N records` and exits 0, or names the first broken entry (`BROKEN at seq N: <reason>`) and exits 1. It detects an edited record, a deleted record, records out of order, a truncated log, a torn write, and a log signed with a different key. Pass `--pubkey` with a key you saved earlier to catch a log that was rebuilt from scratch with a new key.

```bash
hermes ledger show [--last N] [--tool X] [--session S] [--kind K] [--json]
```
A readable timeline. `--last 0` shows everything.

```bash
hermes ledger export --receipt [--session S] [--out receipt.json]
```
A signed JSON receipt of one session (default: the most recent). Records from other sessions that fall inside its range appear only as content-free stubs, so the chain can still be checked without revealing them. Anyone can verify a receipt with the public key alone, with or without Hermes:

```bash
hermes ledger verify-receipt receipt.json --pubkey <base64 key>
python3 verify_receipt.py receipt.json --pubkey <base64 key>    # needs only `cryptography`
```

Also: `hermes ledger key` prints the public key and its id, `hermes ledger note "text"` appends a signed note, and inside a chat `/ledger`, `/ledger verify` and `/ledger show 20` do the same from any surface. The dashboard gets a **Ledger** tab with the timeline and a green or red "chain intact" badge. A bundled skill, `hermes-ledger:ledger-audit`, tells the agent to answer "what did you do?" from the verified log instead of from memory.

## How the chain works

```
body_sha256 = sha256(canonical(record without seq, prev_hash, hash, sig))
hash        = sha256(canonical({"body_sha256", "prev_hash", "seq"}))
sig         = Ed25519(hash)
```

`canonical` is JSON with sorted keys, no whitespace and ASCII escapes. The first record's `prev_hash` is 64 zeros. Each record also carries the signing key's id. Splitting the hash into a body digest and a link digest is what lets a receipt carry stubs. The full format lives in `ledger_core.py`, which imports nothing from Hermes.

## Threat model

**What it proves.** That the log has not been changed since it was written: no record edited, inserted, deleted, reordered or cut off the end, by anyone who does not hold the private key. A receipt proves the same thing to a third party who holds only the public key.

**What it does not prove.**

- **Honesty at write time.** The ledger records what Hermes reported to its hooks. It does not prove a tool did what its output claims, or that the agent's reasoning was sound. A compromised Hermes process can write false records, and they will verify.
- **Against someone who holds the key.** The private key sits on the same machine as the log. Anyone who can read it, which includes anyone with your user account, can rewrite history and re-sign it. Two defences: save the public key somewhere else and pass it to `verify --pubkey`, so a log rebuilt with a new key fails; and export receipts to other people as you go, since a receipt they hold cannot be changed afterwards. Truncating back to an older signed head with the original key is only detectable this way.
- **Perfect redaction.** Redaction is pattern-based. A secret in an unusual shape, under an innocuous key, can reach the log. Result *contents* are never stored, only their hashes.
- **Confidentiality.** The log is plaintext (redacted) in your Hermes home, readable by your user.

## Disclosure

Hooks see every tool call's name and arguments, the result of every tool call (hashed, never stored), and approval prompts. The plugin writes only under `<HERMES_HOME>/plugin-data/hermes-ledger/`, makes no network calls, starts no background processes, runs no shell commands, and never approves, denies, blocks or modifies anything. The log is not pruned; delete the directory to start over (that also deletes the key).

## Development

```bash
python -m pytest            # 52 behaviour tests; real-Hermes E2E tests skip unless `hermes` is on PATH
demo/run_demo.sh --offline  # the demo without Hermes or a model
```

## License

MIT. See `LICENSE`.
