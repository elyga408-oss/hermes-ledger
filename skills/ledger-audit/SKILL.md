---
name: ledger-audit
description: Answer "what did you actually do?" with evidence. Use when the user asks for an audit of the agent's recent actions, wants proof that a tool call happened (or did not), or wants a signed receipt of a session to share with someone else.
version: 0.1.0
metadata:
  hermes:
    tags: [audit, provenance, receipts]
---

# ledger-audit

The hermes-ledger plugin records every tool call, its redacted arguments, the
SHA-256 of its result and every approval decision in a signed, hash-chained log.
Use the log, not your memory of the conversation, when the user asks what you did.

## When to use
- "What did you run?", "Did you touch file X?", "Show me everything you did today."
- "Prove nothing was changed afterwards." / "Give me a receipt I can send to someone."

## Steps
1. Check integrity first with the terminal tool: `hermes ledger verify`.
   - If it prints `BROKEN at seq N`, tell the user plainly that the log was altered
     at entry N and that entries from N onward cannot be trusted. Do not guess what
     the original said.
2. Show the relevant events: `hermes ledger show --last 30`, narrowed with
   `--tool terminal`, `--session <id>` or `--kind approval` as needed.
3. Summarise from the output: which tools ran, with which (redacted) arguments,
   whether each succeeded, and which calls a person approved.
4. For a shareable proof: `hermes ledger export --receipt --out receipt.json`, and
   tell the user the recipient checks it with
   `hermes ledger verify-receipt receipt.json --pubkey <key>` (the key comes from
   `hermes ledger key`, ideally sent over a separate channel), or with the
   standalone `verify_receipt.py` that ships with the plugin.

## Limits to state honestly
- The ledger proves the log was not changed after it was written. It does not
  prove a tool did what its output claims, and it stores result hashes, not results.
- Arguments are redacted on a best-effort basis; say so if asked.
- Your own `hermes ledger ...` commands are recorded too. That is expected.
