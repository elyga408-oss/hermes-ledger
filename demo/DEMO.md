# Demo shot list (target 75 seconds, hard limit 90)

Terminal font at 18pt or larger, dark theme, window about 120 columns wide.
`demo/run_demo.sh` types the terminal part for you, pausing `DEMO_PAUSE` seconds
(default 1.5) before each command. Use `demo/run_demo.sh --offline` for a dry run
with no Hermes or model.

Before recording: `hermes plugins enable hermes-ledger`, run one throwaway
`hermes chat -q ... -Q` so the key exists, and `cd` into a small folder.

| # | time | on screen | voice-over / caption |
|---|---|---|---|
| 1 | 0:00–0:06 | Title card: **Hermes Ledger**, subtitle "a tamper-evident flight recorder for Hermes" | "Your agent ran commands for you. Can you prove what it did?" |
| 2 | 0:06–0:20 | `run_demo.sh` starts: `hermes chat -q "How many files are in this folder? Use the terminal." -Q -t terminal`; Hermes answers | "A tiny task. Hermes uses the terminal tool." |
| 3 | 0:20–0:32 | `hermes ledger show --last 8`: the timeline with `tool_call`, `tool_result`, the result hash, duration | "Every tool call, its redacted arguments and a hash of its result go into a signed, hash-chained log." |
| 4 | 0:32–0:38 | `hermes ledger verify`: green `✔ OK: N records, chain intact` | "One command checks the whole chain." |
| 5 | 0:38–0:48 | Script changes one letter of the recorded command (caption shows `'l' becomes 'L'`), then `hermes ledger verify`: red `✘ BROKEN at seq N: ... record was edited` | "Change a single byte, and verify names the exact entry." |
| 6 | 0:48–0:56 | Restore, `hermes ledger verify`: green again | "Put it back: green." |
| 7 | 0:56–1:08 | `hermes ledger export --receipt`, then `python3 verify_receipt.py receipt.json --pubkey ...`: `OK` | "Export a signed receipt. Anyone can check it with just your public key, no Hermes needed." |
| 8 | 1:08–1:15 | Optional: dashboard **Ledger** tab with the green "chain intact" badge. End card: install line `hermes plugins install hermes-ledger` | "Hermes Ledger. Evidence, not memory." |

Notes for the edit:
- If the agent's answer in shot 2 is slow, cut while it thinks; keep the tool-call line visible.
- Shot 5 is the money shot. Hold the red line for a full second.
- Keep the approval story for the post text, not the video: binding an approval to
  the exact call is shown by `ledger show` as `✔ once via cli -> binds call #5` if a
  dangerous command was approved during the run.
- Do not show `~/.hermes/.env`, API keys, or the `ed25519.key` file on screen.
