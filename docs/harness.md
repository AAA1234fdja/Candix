# The harness

Candix has two halves: the deterministic scanner (`candix scan`) and the
autonomous layer (`candix agent`). The second half is not one loop, it is a set of
capabilities that have to be **on the same object** to be worth anything: a gate
that is not consulted, a review board nobody seeds, a todo list that dies with
the process. `candix/agent/harness.py` is that object. The gate underneath is
now **dual-engine**: Python `candix/agent/intercept.py` and Go `engine/intercept`
corren a la par via `candix/engine_bridge` (see `docs/engine.md`).

```console
$ candix harness
CAPABILITY  MODULE                       STATE
gate        candix.agent.intercept       wired  (dual: candix/engine_bridge → engine/intercept)
targets     candix.agent.intercept       wired  (parallel normalisation)
policy      candix.agent.policy          wired
...
```

`python -m candix harness` hoy reporta **39/39 wired** (17 `engine-*` + 22 Python nativos). Ver `candix/engine_adapter/orchestrator.py:Engine.health()` para el detalle de 17 sub-motores.

`Harness` is a composition root, not a new layer of decisions:

* it decides nothing the gate or the policy does not already decide;
* it never executes a tool, a command or a request;
* every hook is best-effort — a broken webhook, an unwritable artifact directory
  or a crashed reviewer cannot end a run.

## What it wires, and where the hook is

| Capability | Hook point | Effect |
| --- | --- | --- |
| intercept gate | `ToolRegistry._preflight` via `ToolContext.interceptor` → `intercept.score_tool` or `EngineClient.score_risk` when `engine.enabled=true` | every tool call is risk-scored (python-only by default, **a la par** Python+Go `max`+union when enabled) before the handler runs |
| target gate | same → `EngineClient.normalize_target` when enabled | URL, host, `host:port` and CIDR arguments are normalised (python-only, parallel when enabled) and checked against the engagement |
| command gate | `notify.CommandChannel` and `candix gate` → `CommandGate` or `InterceptProxy.check_command_gate` when enabled | argv prefix rules, code-owned denylist, risk ceiling, and the targets read out of the argv |
| targeting | `AgentLoop._planner_state` → `PlannerState.next_targets` | the planner sees the five highest-value endpoints with the reasons they scored |
| todos | `Harness.on_event` on `intent.start` / `intent.finish` / `intent.blocked` | each intent becomes a durable todo; failures are parked with a reason |
| poc | `Harness.finish` | `poc/<n>-<slug>/poc.{sh,py,js,http}` plus a README per finding |
| review | `Harness.finish` | the board is seeded from the findings and written to `review.json` / `review.md` |
| notify | `Harness.finish` | one redacted, deduplicated message per run, only above `--notify-min-severity` |
| evidence, audit, scorecard, triage, compliance, insights, bundle | `AgentSession.snapshot` and the CLI writers | unchanged, but now reachable from one object (`harness.summary()`) |

The gate is the part that matters most. It runs *after* the scope guard and
*before* the handler, **en paralelo Python+Go when `engine.enabled=true`**, so a refusal is cheap, visible and attributable:

| Refusal | Rule | Seen in |
| --- | --- | --- |
| host outside the engagement | `scope` | `session.json → harness.gate.entries`, `tools.blocked` |
| cloud metadata address | `metadata` | same, plus `harness.blocked` |
| private or reserved address | `private` | same |
| risk at or above `--gate-max-risk` | `risk` | same |
| interpreter, launcher, package manager, destructive argv | `denylist` | `candix gate`, `notify` deliveries |

A gate that raises fails **closed**: the call is refused with `gate failed: …`
and the counter `intercept.failed` increments.

## Commands

```console
$ candix gate "rm -rf /"                       # exit 10: denylist
$ candix gate cat notes.txt --allow-prefix cat # exit 0: allowlist
$ candix gate curl http://169.254.169.254/ --json
$ candix harness --target https://app.example.com --target 169.254.169.254
$ candix harness --run runs/latest
$ candix review runs/latest --approve --reviewer ana
```

`candix gate` exits `0` when the command would run and `10` when it would be
refused, so it works as a shell pre-flight check. Quote the command: unquoted
tokens starting with `-` are parsed as options.

## Run flags

| Flag | Default | Effect |
| --- | --- | --- |
| `--gate-max-risk` | `70` | risk at or above which a tool call is refused |
| `--allow-command` | none | argv prefixes command tools may use (the denylist still wins) |
| `--allow-private` | off | permit private/loopback targets outside the engagement |
| `--no-gate` | gate on | disable the intercept gate |
| `--no-poc` / `--no-review` / `--no-todos` / `--no-targeting` | on | skip that artifact |
| `--notify-webhook` / `--notify-slack` / `--notify-file` / `--notify-command` | off | where the run summary goes |
| `--notify-min-severity` | `high` | how bad a finding must be to notify |

Artifacts land next to the reports: `poc/`, `review.json`, `review.md`,
`todos.json`. `session.json` carries the whole `harness` block, so a run can be
audited after the fact without reading the journal.

## Tests

`tests/test_agent_harness.py` holds the invariants: the gate refuses
out-of-scope calls through the real registry, fails closed when it crashes,
the harness records what it refused, `finish()` writes the PoC bundle, the board
and the todos even when a finding is malformed, notifications respect the
severity floor, and **no module in `candix/agent` is an orphan** — a capability
nobody imports is a capability the harness does not have.
