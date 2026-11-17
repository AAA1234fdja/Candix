# Reference material

Read [`NOTICE.md`](NOTICE.md) first: provenance, why each file is here, and the
AGPL/MIT boundary.

Nothing in this directory is imported, packaged or executed by Candix. The
Python equivalents live in:

| ARTEX reference | Candix |
| --- | --- |
| `intercept/risk.go`, `guard/guard.go` | `candix/agent/intercept.py`, `candix/agent/policy.py` |
| `intercept/argv.go`, `intercept/alwaysallow_denylist.go` | `candix/agent/intercept.py` (`ArgvPrefix`, `AlwaysAllowDeny`) |
| `intercept/target.go`, `intercept/target_dial.go` | `candix/agent/intercept.py` (`TargetGate`) |
| `agent/budget.go` | `candix/agent/budget.py` |
| `agent/noise_profile.go`, `egress/*.go` | `candix/net/ratelimit.py`, `candix/agent/guard.py` |
| `agent/untrusted_prompt.go`, `agent/data_envelope.go` | `candix/agent/tools.py` (`untrusted_output`), `candix/llm/guardrails.py` |
| `agent/planner.go`, `agent/worker.go` | `candix/agent/planner.py`, `candix/agent/worker.py`, `candix/agent/adaptive.py` |
| `agent/toolcatalog.go` | `candix/agent/toolset.py` |
| `evidence/store.go` | `candix/agent/evidence_chain.py` |
