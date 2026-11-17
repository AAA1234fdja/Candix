# The engine tree

`engine/` is an archived Go backend and React console, kept in this repository as
the source of the ideas Candix's autonomous layer is built on: the pre-tool-use
gate, argv and target normalisation, the egress governor, the budget tree, the
data envelopes. It is a **renamed fork**, not a dependency:

* nothing in `candix/` imports or executes it;
* `pyproject.toml` excludes it from the package;
* it is not built in CI and it is not part of a Candix release.

## Layout

| Path | What it holds |
| --- | --- |
| `engine/intercept/` | risk scoring, argv parsing and prefix rules, target normalisation and dial-time checks |
| `engine/guard/` | the pre-tool-use hook, audit trail, failure attribution |
| `engine/agent/` | planner, workers, tool catalogue, budgets, untrusted-data envelopes |
| `engine/server/` | HTTP API, sessions, assets, approvals |
| `engine/db/` | schema and migrations for the graph stores |
| `engine/egress/`, `engine/traffic/` | outbound governor, MITM proxy and rewrite rules |
| `engine/notify/`, `engine/report/`, `engine/evidence/` | delivery channels, reporting, evidence persistence |
| `engine/web/` | the Next.js console |
| `engine/scripts/`, `engine/*.sh` | build, install, update and benchmark scripts |
| `engine/.github/` | the workflows the engine shipped with (archived) |
| `docs/engine/` | the engine's own documentation, changelog, security policy and screenshots |
| `skills/` | the engine's skills, merged into Candix's skill directory (same `SKILL.md` format) |

## Build

The image builds from the repository root, because the Docker context has to see
both trees:

```bash
docker compose -f engine/docker-compose.yml up -d --build   # engine + postgres
docker build -f engine/Dockerfile .                         # image only
```

## Licence

The engine tree is **AGPL-3.0** (`engine/LICENSE`); Candix is MIT. Renaming a fork
does not change its licence: distributing these files — in any directory, under
any name — makes the distribution subject to the AGPL. Keep the tree out of
release artifacts (the packaging exclude enforces it) or relicense the whole
distribution.

## Where Candix mirrors it

| Engine | Candix |
| --- | --- |
| `engine/intercept/` | `candix/agent/intercept.py` |
| `engine/guard/` | `candix/agent/guard.py`, `candix/agent/policy.py` |
| `engine/agent/budget.go` | `candix/agent/budget.py` |
| `engine/agent/untrusted_prompt.go`, `data_envelope.go` | `candix/agent/tools.py`, `candix/llm/guardrails.py` |
| `engine/agent/planner.go`, `worker.go` | `candix/agent/planner.py`, `worker.py`, `adaptive.py` |
| `engine/egress/` | `candix/net/ratelimit.py` |
| `engine/evidence/` | `candix/agent/evidence_chain.py` |

The Python side reimplements the behaviour; it does not copy code, identifiers or
structure.
