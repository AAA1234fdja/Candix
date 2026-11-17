# Adaptive mode

A deterministic scanner runs a fixed catalogue over every input it finds. Its
ceiling is the catalogue: whatever the authors did not write, it will never try.
Adaptive mode replaces that with three feedback loops, each of which can change
what the next request is:

1. **Anomalies** — the target is its own baseline. A response that differs from
   the same endpoint's usual behaviour is the cheapest signal available.
2. **Hypotheses** — every anomaly, parameter name, endpoint shape and unverified
   finding becomes a belief with a prior, a posterior and a cost.
3. **Bandit** — techniques are arms; findings and new assets are the reward. The
   run spends its turns on what has been paying off against *this* target.

```bash
candix agent https://app.example.com --engagement acme.json \
  --adaptive --adaptive-strategy ucb \
  --goal "prove the most severe issue" --autonomy auto --exploit
```

## Anomalies

`agent.anomaly` keeps a baseline per endpoint (status distribution, response
length median and MAD, timing median and MAD, header set) and reports:

| kind | what changed | usual hint |
| --- | --- | --- |
| `status` | 200 → 401/403/429/500 | authz, rate limit, error |
| `length` | body much longer or shorter | reflection, template |
| `timing` | response far from the median | blind injection |
| `header` | unusual headers appear | CORS, redirect |
| `reflection` | the marker came back in the body | XSS, SSTI |
| `error` | SQL/trace/path signatures in the body | SQLi, LFI, RCE |
| `transport` | connection-level failure | availability |

Timing and length use robust statistics (median, median absolute deviation), so
one slow response does not poison the baseline. `from_observation` converts tool
payloads into samples; `absorb` does it for a whole batch.

## Hypotheses

`agent.hypotheses` stores beliefs with numbers:

```text
posterior = sigmoid(logit(prior) + Σ log(P(signal | true) / P(signal | false)))
```

Each test has a detection rate and a false-alarm rate that depend on its
strength; `information_gain` is the entropy the test is expected to remove and
`value` divides it by cost and multiplies it by the severity weight of the class.
Tests are ranked by value, never reissued after they run, and settled beliefs
(p ≥ 0.9 or ≤ 0.08) drop out of the queue.

Seeding is what makes the first turn non-trivial:

| source | example belief | prior |
| --- | --- | --- |
| parameter name | `parameter id on /api/users is injectable` | 0.45 |
| endpoint shape | `introspection is enabled on /graphql` | 0.50 |
| anomaly | `sqli on /search caused by the input` | 0.25 + 0.5·strength |
| unverified finding | `idor at /profile?id=1 reproduces` | 0.60 |
| verified finding (with `--exploit`) | `idor at /profile?id=1 can be exploited` | 0.50 |

Tests that would hit the same tool for the same vulnerability class share one
intent — a detector run already covers every endpoint — so three IDOR beliefs
cost one call, not three. Every covered belief is tagged on that intent and all
of them are updated by the outcome.

`test_for` maps a belief to a tool: `detect.run` with restricted categories,
`web.probe`, `graphql.query`, `auth.flow`, `jwt.inspect`, or `exploit.run` once
the belief is supported and exploitation is allowed.

## Bandit and modes

`agent.adaptive.Bandit` is UCB1 by default and Thompson sampling on request.
Reward is findings (capped), new assets (capped) and a small completion credit;
refusals and failures return zero, so a blocked arm decays on its own.

The controller picks a mode each turn:

| mode | chosen when | intents |
| --- | --- | --- |
| `verify` | material findings are unverified | `http.request` on the finding URL |
| `exploit` | a belief is supported and `--exploit` is on | `exploit.run` |
| `test` | a belief has value above the floor | the belief's tool |
| `explore` | stalled, or nothing to test | highest-UCB arms |

If the chosen mode yields nothing, the controller cascades (verify → test →
exploit → explore) before handing the turn to the wrapped planner. Refused
intents are remembered (`reject`) and never re-emitted, which is what stops a
run from hammering the same approval gate.

## Priors across runs

`agent.learning` keeps Beta parameters per tool, scoped to a fingerprint of the
target hosts, in `~/.candix/agent-priors.json` (override with `--priors` or
`CANDIX_AGENT_PRIORS`). After a run, per-tool call/finding counts update the
priors, which decay so old campaigns do not dominate. The next run seeds the
bandit from them, so turn one against the same class of target already prefers
what worked.

Nothing about a target is shared across fingerprints, and the file stores counts
and Beta parameters only — no URLs, bodies or credentials.

## What the run records

* `session.json` → `adaptive.state`, `adaptive.bandit`, `adaptive.hypotheses`,
  `adaptive.anomalies`, `priors`
* `adaptive.md` → the same picture as a table, in the artifact directory
* journal events: `plan`, `intent.blocked`, `intent.finish`, `contract.violation`

## Limits worth knowing

* The bandit optimises for findings *and* coverage; on a target with one real
  bug it will still spend turns exploring. Lower `--explore-ratio`, or narrow
  the goal.
* Priors are per host fingerprint. A staging host with the same software but a
  different name starts from scratch — intentional, because sharing across names
  is a data-leak risk.
* Hypotheses propose tests; the policy still scores, gates and can refuse every
  one of them. Adaptivity never widens scope.
