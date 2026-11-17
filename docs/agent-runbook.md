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
approve with items unchecked:

```python
from candix.agent.review import ReviewBoard, block_release

board = ReviewBoard.load("runs/review.json")
board.seed(findings)
ok, reason = block_release(board)
```

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

## Common problems

- **No endpoints found**: the target blocks the crawler or requires a session.
  Add `--header` credentials via `http.request` intents or use an API spec.
- **All intents blocked**: the autonomy level is `observe`, or the engagement does
  not allow the target host.
- **Findings but no proofs**: exploitation is disabled, or no technique matched the
  finding class. Check `exploit.run` in the journal.
- **Model planner unavailable**: the client falls back to the heuristic planner and
  says so in the plan reasoning; the run continues.
