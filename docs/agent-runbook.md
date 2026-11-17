# Agent runbook

Operational notes for running the agent against a real engagement.

## Before the first run

1. Create the engagement document with the exact hosts and a request ceiling.
2. Decide whether exploitation is allowed. If the answer is "maybe", leave it off
   and re-run later with `--exploit`.
3. Pick a profile: `safe` for production, `lab` for a test target, `deep` when the
   surface is large.
4. Run a dry run first:

```bash
candix agent https://app.example.com --engagement acme.json --dry-run --json | jq .
```

The dry run prints the plan, the gate decision for each intent, and the simulated
cost in requests and seconds. If the simulation does not fit the remaining
budget, adjust `--turns`, `--tool-calls` or the goal before sending traffic.

## Running

```bash
candix agent https://app.example.com \
  --engagement acme.json \
  --goal "prove the most severe authorization issue" \
  --autonomy auto --approvals auto \
  --turns 12 --tool-calls 80 --seconds 900 \
  --formats markdown,json,sarif,html \
  --metrics runs/agent.prom
```

Exit codes: `0` clean, `10` findings, `1` error, `2` usage, `130` interrupted.

## Reading the output

| Artifact | What it answers |
| --- | --- |
| `agent-*.md` | narrative, plan table, findings, lessons |
| `agent-*.sarif` | findings for code scanning dashboards |
| `evidence-chain.json` | which exchange supports which claim |
| `session.json` | budget, telemetry, graphs, policy |
| `insights.md` | where the time went and what to change |
| `replay/` | runnable proofs with credentials as env vars |
| `poc/` | one curl/python/js/httpie reproduction per finding |
| `review.json`, `review.md` | reviewer checklist per finding, and the board as prose |
| `todos.json` | what the run meant to do and what it parked, for the next run |
| `journal.jsonl` | every event, in order |

## When a run stops early

| Stop reason | Action |
| --- | --- |
| `turn budget exhausted` | raise `--turns`, or narrow the goal |
| `time budget exhausted` | raise `--seconds`, or run `detect.run` separately |
| `tool-call budget exhausted` | raise `--tool-calls`; check insights for a hot tool |
| `no progress after repeated stalls` | look at `insights.md`; the planner is repeating |
| `awaiting approval` | run with `--approvals auto` or approve and `--resume` |
| `goal not provable` | record facts with `facts.add`, then retry `goal.prove` |

## Review before delivery

Findings are not final until someone signs off. `agent.review` builds a checklist
per finding from the knowledge base, tracks reviewer comments, and refuses to
approve with items unchecked. The run already seeds the board and writes it:

```bash
candix review runs/latest            # status, pending items, release verdict
candix review runs/latest --approve --reviewer ana
candix review runs/latest --markdown > review.md
```

```python
from candix.agent.review import ReviewBoard, block_release

board = ReviewBoard.load("runs/review.json")
board.seed(findings)
ok, reason = block_release(board)
```

## Adaptive runs

Use `--adaptive` when the target is worth the extra turns: it re-tests what the
target's own responses flag instead of walking the catalogue. Check
`adaptive.md` afterwards — the arm table says which technique paid off, and the
hypothesis table says what is still open. If a run keeps landing in `explore`
with no findings, narrow the goal or drop `--explore-ratio`.

## CI integration

Use the diff gate so a scheduled run fails only on regressions:

```bash
candix agent "$TARGET" --engagement acme.json --formats json --out runs/new
candix diff runs/old/agent.json runs/new/agent.json --fail-on high
```

Keep the agent's own audit in the pipeline too: `session.json` contains
`audit.clean`, and `violations` names anything that went out of scope.

## Cost and safety knobs

| Knob | Effect |
| --- | --- |
| `--tokens`, `--cost` | model spend ceilings |
| `--max-rps` | request rate ceiling enforced by the scope guard |
| `--approvals ask` | stops before any high-risk intent |
| `--no-llm` | deterministic planner, zero model cost |
| `--playbook-limit` | stop seeding after N playbook steps |
| `--adaptive` | choose tests by evidence value instead of a fixed order |
| `--adaptive-strategy thompson` | sharper exploration when arms are close |
| `--explore-ratio` | share of turns reserved for exploration |
| `--priors` / `--no-priors` | where cross-run priors live, or disable them |
| `--gate-max-risk`, `--allow-command` | risk ceiling and argv prefixes for tool calls and command channels |
| `--no-gate` | turn the intercept gate off (only for a target you already know) |
| `--no-poc`, `--no-review`, `--no-todos`, `--no-targeting` | skip the harness artifacts |
| `--notify-webhook`, `--notify-slack`, `--notify-file`, `--notify-command` | tell someone when a run finds something |
| `--notify-min-severity` | how bad a finding has to be before it is worth a message |

## What the harness connects

`candix harness` lists every capability and the module that provides it; `candix
harness --run runs/latest` prints the gate, PoC, review, todo and notification
block of a finished run. The composition root is `candix/agent/harness.py`:

| Capability | Effect on a run |
| --- | --- |
| intercept gate (dual Python+Go a la par) | every tool call is risk-scored and target-checked **en paralelo** (`engine_bridge` → `engine/intercept`) before the handler |
| targeting | the planner sees the five highest-value endpoints, not just a list |
| todos | each intent becomes a durable todo; failures are parked for the next run |
| poc | findings arrive with curl, python, js and httpie reproductions |
| review | the board is seeded per finding and blocks release until signed off |
| notify | one message per run, deduplicated, redacted, gated if it shells out |

## Common problems

- **No endpoints found**: the target blocks the crawler or requires a session.
  Add `--header` credentials via `http.request` intents or use an API spec.
- **All intents blocked**: the autonomy level is `observe`, or the engagement does
  not allow the target host.
- **Findings but no proofs**: exploitation is disabled, or no technique matched the
  finding class. Check `exploit.run` in the journal.
- **Model planner unavailable**: the client falls back to the heuristic planner and
  says so in the plan reasoning; the run continues.
- **"refused by the gate"** in the summary: the call was out of scope or above the
  risk ceiling. `candix gate "<the command>"` answers why; the same reasons are in
  `session.json → harness.gate.entries`.
- **Nothing was notified**: no finding reached `--notify-min-severity`, which
  defaults to `high`. Lower it, or check `harness.notify.deliveries` in the snapshot.
