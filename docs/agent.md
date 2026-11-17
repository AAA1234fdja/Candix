# The Candix agent

`candix agent` is the autonomous layer on top of the scanner. It takes a goal, plans
intents, executes them with real tools, records evidence in a graph, and closes with a
proof instead of a feeling.

```bash
candix agent https://app.example.com \
  --goal "find and prove the most severe issue" \
  --authorized alice --exploit --autonomy auto --profile lab \
  --turns 12 --formats markdown,json,sarif,html
```

Everything below describes what runs when you type that.

## The shape of a run

```
goal ──► planner ──► intents ──► policy gate ──► worker ──► tools ──► HTTP
          ▲              │            │            │           │
          │              │            ▼            ▼           ▼
      blackboard ◄───────┘        approvals   observations   evidence
          ▲                                       │           │
          └──────────── assets · facts · journal ◄┘◄──────────┘
```

| Piece | Module | Responsibility |
| --- | --- | --- |
| Goal | `agent.models.Goal` | statement, success criteria, constraints |
| Planner | `agent.planner` | `HeuristicPlanner` offline, `LLMPlanner` with schema-checked intents |
| Scheduler | `agent.scheduler` | phase-weighted priority, dependency resolution, retries |
| Worker | `agent.worker` | `DeterministicWorker` (planned tool), `LLMWorker` (tool loop) |
| Tools | `agent.toolset` | 15 tools with schemas, caps and timeouts |
| Guard | `agent.guard` | scope, deny list, red lines, rate limiting |
| Policy | `agent.policy` + `agent.intercept` (↔ `engine/intercept` when `engine.enabled=true`) | risk scoring (python-only, parallel `max`+union when enabled), autonomy levels, approval requirement |
| Approvals | `agent.approvals` | queue with risk ceiling and persistence |
| Facts | `agent.facts` | claims with provenance, merge and conflict handling |
| Graph | `agent.graph` | hosts, services, endpoints, parameters, technologies, findings |
| Blackboard | `agent.blackboard` | shared scratch state and anchor links between graphs |
| Budget | `agent.budget` | turns, intents, tool calls, tokens, seconds, cost |
| Journal | `agent.journal` | append-only JSONL of everything that happened |
| Verifier | `agent.verifier` | re-issues the request behind each finding |
| Reflection | `agent.reflection` | lessons derived from the run, stored for later |
| Reporting | `agent.reporting` | run summary in markdown and JSON |
| Report bridge | `agent.report_bridge` | the run rendered through the scanner's SARIF/HTML/JUnit renderers |
| Playbooks | `agent.playbooks` | named, parameterised plans that seed a run |
| State | `agent.state_io` | save and resume a session across stops |
| Todos | `agent.todolist` | durable follow-ups the next run picks up |
| Insights | `agent.insights` | telemetry analysis and tuning advice |
| Audit | `agent.audit` | what the agent itself did: scope, caps, secrets, chain |
| Diffing | `agent.diffing` | new, fixed, escalated findings between runs |
| Metrics | `agent.metrics_export` | Prometheus/OpenMetrics export |
| Knowledge | `agent.knowledge` | per-class verification, payload and remediation guidance |
| Techniques | `agent.techniques` | ATT&CK coverage of what ran and what is still open |
| Notify | `agent.notify` | Slack, Discord, webhook, file and command channels with dedupe |
| PoC | `agent.poc` | curl/Python/Node/http-file proofs with credentials as env vars |
| Bundle | `agent.reports_bundle` | hashed, verifiable delivery package of a run |
| Anomaly | `agent.anomaly` | per-endpoint baselines and deviations worth a test |
| Hypotheses | `agent.hypotheses` | beliefs with priors, posteriors and information value |
| Adaptive | `agent.adaptive` | bandit, mode selection and the adaptive planner |
| Learning | `agent.learning` | cross-run priors scoped to a target fingerprint |
| Tri-age | `agent.triage` | de-duplication, ranking, chains, risk and grade |
| Evidence | `agent.evidence_chain` | hash-chained records anchored to assets and facts |

## The loop

One turn is: plan, gate, execute, absorb.

1. **Plan.** The planner receives `PlannerState` — goal, targets, coverage, findings,
   attempted tools, remaining turns. It returns up to `max_intents_per_turn` intents or a
   `finish` decision with a reason.
2. **Gate.** `RiskPolicy` scores each intent. Anything above `max_risk_auto` needs approval;
   anything above `max_risk_approved` is refused outright. The scope guard independently
   rejects out-of-scope hosts and denied paths.
3. **Execute.** The worker runs the intent. The deterministic worker calls the planned
   tool; the LLM worker loops up to `worker_max_steps` tool calls, with tool output framed
   as `UNTRUSTED_OUTPUT`.
4. **Absorb.** Findings become graph nodes, parameters extend the asset graph, proofs land
   in the result, facts go to the blackboard, and lessons accumulate.

The loop stops on: goal proven, finish decision, turn cap, intent cap, tool-call cap, token
budget, wall clock, repeated stalls, or a pending approval when `stop_on_approval` is set.

## Coverage drives planning

The planner is not a fixed script. It reads coverage from the asset graph:

| Coverage state | Next intents |
| --- | --- |
| 0 endpoints | crawl, fingerprint |
| endpoints, no findings | detector catalogue, probe uncovered endpoints |
| findings, unverified | re-issue the request for the top material findings |
| verified findings, few facts | record facts with provenance |
| provable facts | `goal.prove` |
| proof accepted | finish |

That is why `recon.crawl` writes every discovered URL into the graph: without the write-back
the planner cannot tell that reconnaissance already happened, and it would crawl forever.

## Tools

| Tool | Phase | Risk | Purpose |
| --- | --- | --- | --- |
| `http.request` | any | 0.1 | one request, bounded body |
| `http.batch` | detect | 0.2 | same method across up to 40 URLs |
| `http.replay` | verify | 0.1 | resend a recorded exchange |
| `recon.crawl` | recon | 0.1 | breadth-first discovery, writes endpoints |
| `recon.fingerprint` | recon | 0.1 | technologies from headers and body |
| `recon.robots` | recon | 0.1 | robots.txt and sitemap entries |
| `scope.map` | recon | 0.1 | host resolution and scope seeding |
| `detect.run` | detect | 0.35 | the detector catalogue |
| `fuzz.run` | detect | 0.45 | parameter fuzzing with the payload catalogue |
| `auth.test` | detect | 0.4 | authentication and session checks |
| `exploit.run` | exploit | 0.8 | proof-grade exploitation via `candix.exploit` |
| `facts.add` / `facts.list` | verify | 0.05 | provenance-tracked claims |
| `endpoints.list` / `findings.list` | any | 0.05 | read the graph |
| `goal.prove` | verify | 0.05 | close the goal from facts |
| `report.write` | report | 0.05 | materialise a report |
| `web.probe` | recon | 0.2 | sensitive paths, backups and method probing |
| `api.spec` | recon | 0.1 | OpenAPI/Swagger discovery and ingestion |
| `graphql.query` | recon | 0.2 | introspection or a narrow query |
| `auth.flow` | detect | 0.4 | login form, session rotation, cookie flags |
| `jwt.inspect` | detect | 0.5 | token issues, short secret list, alg=none |
| `oauth.flow` | recon | 0.1 | OIDC metadata and redirect URI matching |
| `ws.probe` | recon | 0.2 | WebSocket handshake and origin checks |
| `fuzz.run` | detect | 0.45 | bounded mutation campaign over parameters |

Each tool declares `max_calls` and `timeout`. Exceeding the cap fails the intent with
`exceeded its call allowance`, which the planner sees and avoids repeating.

## Facts and proof

Findings are observations. Facts are claims with a source:

`target_response`, `tool_output`, `third_party_intel`, `operator_input`, `inference`.

`goal.prove` refuses to close a goal on `inference` alone or on a fact that was never
observed. When no claim matches the goal sentence it falls back to the provable facts the
run collected, and returns them with the proof so a reviewer can check each one.

## Budgets

```bash
--turns 12          plan/act cycles
--intents 40        intents executed
--tool-calls 80     tool invocations
--seconds 900       wall clock
--tokens 200000     model tokens
--cost 5.0          model spend in USD
```

A budget exhaustion is not an error: the run stops, reports what it has, and records a
lesson about what was cut short.

## Approvals

With `--autonomy assist` (the default) risky intents wait in the approval queue:

- `--approvals ask` stops the run and writes `approvals.json` for the operator.
- `--approvals auto` auto-approves anything at or below `max_risk_approved` (0.9).

The queue is persisted under the artifact directory, so a resumed run can continue where
the approval was requested.

## Artifacts

Every run writes to `--out` (default `agent-runs`):

```
agent-runs/20261117-101500/
  agent-20261117-101500.md      run report
  agent-20261117-101500.json    machine-readable run
  agent-20261117-101500.sarif   findings for code scanning
  evidence-chain.json           tamper-evident evidence
  session.json                  budget, policy, graphs, telemetry
  journal.jsonl                 append-only event log
  approvals.json                pending approvals
```

## Adaptive mode

The deterministic planner walks a fixed order; the adaptive planner chooses each
turn from evidence. It baselines every endpoint, turns deviations into beliefs
with posteriors, and spends turns on the tests with the highest information value
while a bandit tracks which technique pays off against this target:

```bash
candix agent https://app.example.com --engagement acme.json --adaptive --exploit
```

Modes: `verify` (unverified findings first), `test` (best belief), `exploit`
(supported beliefs), `explore` (highest-uncertainty arms when stalled). Refused
intents are remembered, so the run does not re-ask the same approval gate.
Cross-run priors live in `~/.candix/agent-priors.json`, scoped per target
fingerprint. Details: [`docs/agent-adaptive.md`](agent-adaptive.md).

## Playbooks

A playbook is a plan an operator already knows they want, parameterised per target:

```bash
candix agent --list-playbooks
candix agent https://app.example.com --authorized alice --playbook recon-sweep
```

Built-in: `recon-sweep`, `exposure-sweep`, `api-review`, `auth-review`,
`injection-sweep`, `proof-run`. Drop JSON files into `playbooks/` to add your own;
`Playbook.from_dict` validates phases and tools before a step can run.

The playbook seeds the first turn and then hands control to the planner, so a run
never gets stuck repeating a step that returned nothing.

## Resume, todos and diffs

A run that stops for a budget or an approval can continue:

```bash
candix agent https://app.example.com --engagement acme.json --resume agent-runs/20261117-1015/state.json
```

State covers the asset graph, facts, budget counters and unfinished intents.
`TodoList` records the follow-ups that did not fit, and the next run can read
them before planning anything new.

Two runs can be compared for regressions, which is what a CI job wants:

```python
from candix.agent.diffing import from_files, regression_gate

diff = from_files("previous.json", "current.json")
ok, reason = regression_gate(diff, fail_on="high")
```

## Metrics and self-audit

`--metrics run.prom` writes Prometheus text: duration, findings, proofs, per-tool
seconds, budget usage and counters. `agent.audit` checks the agent's own
behaviour after the fact: hosts outside scope, tools past their cap, secrets that
reached a prompt, and whether the evidence chain still verifies.

## Delivering a run

```bash
candix agent https://app.example.com --engagement acme.json --out runs/2026-11-17
candix bundle runs/2026-11-17 --zip runs/2026-11-17.zip --prune
candix bundle runs/2026-11-17 --verify
```

`bundle` writes `manifest.json` with a SHA-256 per file plus a generated
`README.md`; `--verify` re-hashes everything and fails if a byte changed. The
same directory holds `insights.md`, `evidence-chain.json`, `replay/` and optional
Prometheus metrics, so the client receives one tree they can check.

Notifications read the same run: `agent.notify` has a router with a severity
floor, a duplicate window and redaction, and ships Slack, Discord, webhook, file
and command channels. Proofs (`agent.poc`) render each finding as a runnable
curl/Python/Node/http-file bundle with credentials replaced by env placeholders.

## Extending

Add a tool:

```python
from candix.agent.tools import Tool

def rce_check(ctx, arguments):
    ...
    return {"summary": "...", "findings": [...]}

registry.register(Tool("rce.check", "Attempt a bounded RCE proof.", rce_check,
                       {"type": "object", "properties": {"url": {"type": "string"}}},
                       max_calls=2, tags=("exploit",)))
```

Add an observation contract in `agent/contracts.py` so malformed payloads are caught at the
boundary instead of failing a consumer.

Add a prompt in `llm/prompts.py` and reference it by name; `validate_all()` runs in the
test suite.

## Limitations

- The heuristic planner is deliberately shallow: it covers the recon → detect → verify →
  prove path, not creative pivoting.
- `detect.run` dominates runtime on a large target; the simulator estimates it first.
- Model-driven planning requires a provider key or a local Ollama server.
- Exploitation needs `--exploit` **and** an engagement document that allows it; both are
  checked before a packet is sent.
