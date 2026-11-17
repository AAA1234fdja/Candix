# ARTEX reference material

Candix keeps a verbatim mirror of the ARTEX sources it learned from, in
[`vendor/artex-reference/`](../vendor/artex-reference/NOTICE.md): **838 of 855
tracked files (98.01%)**, 8.88 MB. The rule is mechanical — every source and
documentation file is copied, only images and fonts are left out — and
`MANIFEST.json` records each file with its size and SHA-256. Nothing there is
imported, packaged or executed; `pyproject.toml` excludes `vendor*`, and a test
fails if any `candix` module imports it.

## What was copied

The whole tree from `BaaRai/ARTEX@6337341` (fork of `Autumn-27/ARTEX`), because a
mirror answers questions a curated excerpt cannot. Reading order, though, is
still the risk-first one below: **the code that decides what the agent may do,
then the loop that makes those decisions observable.**

| Layer | Files | Why it is the risky part |
| --- | --- | --- |
| Safety boundary | `guard/guard.go`, `intercept/risk.go`, `intercept/alwaysallow_denylist.go`, `intercept/argv.go`, `intercept/target.go`, `intercept/target_dial.go` | A wrong allow rule, a missing denylist entry or a sloppy target normalisation turns the agent into an unbounded tool. These tables are the difference between an assessment and an incident. |
| Egress | `egress/egress.go`, `egress/pace.go` | Every platform-owned request passes here; pacing, jitter and per-host concurrency are what keep a run from becoming a DoS. |
| Agent core | `agent/budget.go`, `agent/noise_profile.go`, `agent/untrusted_prompt.go`, `agent/data_envelope.go`, `agent/planner.go`, `agent/worker.go`, `agent/toolcatalog.go` | Budgets, prompt-injection framing and the planner/worker split are the parts that are hard to get right and easy to get subtly wrong. |
| Evidence | `evidence/store.go` | A finding without an integrity-checked record is an opinion. |

The mirror also contains the volume — tool adapters (`agent/tools.go`, 108 KB),
the HTTP proxy, DB migrations, the React UI, the integrations — which is useful
for comparing behaviour, not for borrowing design decisions. Only 17 binary
assets are absent (15 PNGs, 1 SVG, 1 CSS sprite set), listed in
`MANIFEST.json → skipped`.

## What Candix implemented instead

The behaviour was reimplemented in Python, for this codebase, without copying
ARTEX text, identifiers or structure:

| ARTEX | Candix | Notes |
| --- | --- | --- |
| `intercept/risk.go` | `candix/agent/intercept.py` → `score_command`, `score_file_write`, `score_web`, `score_intent` | Same idea: deterministic 0..100 score, additive signals in table order, reasons attached, thresholds 30/70. The signal table is our own wording and patterns, extended with an `intent` scorer. |
| `intercept/argv.go` | `argv_prefix`, `prefix_matches`, `split_command`, `ARGV_ARITY` | Arity table for the programs Candix actually launches; `shlex` instead of a shell parser, with a tolerant fallback. |
| `intercept/alwaysallow_denylist.go` | `ALWAYS_ALLOW_DENY`, `AlwaysAllowDeny.check` | An argv allow rule can never name an interpreter, a launcher, a package manager or a destructive tool. |
| `intercept/target.go` | `normalise_target`, `TargetGate` | Scheme default ports, IDNA, IPv4-mapped, hex/octal forms, CIDR, metadata address and hostname blocking. |
| `guard/guard.go` | `CommandGate` + `AuditEntry` | One decision per call, with an audit entry and a summary. |
| `agent/budget.go` | `candix/agent/budget.py` | Already present: turns, tool calls, tokens, seconds, intents, consecutive failures. |
| `agent/untrusted_prompt.go`, `agent/data_envelope.go` | `Tool(untrusted_output=…)`, `candix/llm/guardrails.py`, `candix/agent/facts.py` | Provenance on facts, `UNTRUSTED_OUTPUT` framing on tool payloads. |
| `agent/planner.go`, `agent/worker.go` | `planner.py`, `worker.py`, `adaptive.py` | Planner/worker split plus the adaptive controller. |
| `evidence/store.go` | `evidence_chain.py` | Hash-chained exchanges bound to findings. |

## Using the Python gate

```python
from candix.agent.intercept import CommandGate

gate = CommandGate(allowed_prefixes=["curl", "dig"], targets=["app.example.com"], max_risk=70)
gate.check("curl https://app.example.com/x", targets=["https://app.example.com/x"]).allowed  # True
gate.check("python3 -c 'import os'").allowed                                                 # False (denylist)
gate.check("curl http://169.254.169.254/", targets=["http://169.254.169.254/"]).allowed       # False (scope)
```

`notify.CommandChannel` runs the same gate before executing, so a configured
notification command cannot silently become a remote shell.

## Licensing

ARTEX is AGPL-3.0; Candix is MIT. The mirror is source material for study and
must not ship inside a distributed Candix artifact under MIT terms. With 98% of
the upstream tree present, this is no longer a couple of reference files: treat
`vendor/artex-reference/` as an AGPL component of the repository.
See [`vendor/artex-reference/NOTICE.md`](../vendor/artex-reference/NOTICE.md)
for the full statement and the three options if distribution is planned.
