# Candix

Candix is an authorization-first security testing harness: it maps a web application,
checks it against a catalogue of detectors, optionally proves exploitable issues, and
turns the result into reports that auditors, engineers and CI systems can consume.

Everything here is standard-library Python (3.11+), so the tool runs from a checkout on
any host without a dependency install step.

## Agent mode

The agent plans its own work, runs real tools, and closes with evidence instead of
a hunch:

```bash
candix agent https://app.example.com \
  --authorized alice --exploit --autonomy auto --profile lab \
  --adaptive --goal "prove the most severe issue" --formats markdown,json,sarif
```

It crawls, fingerprints, probes for exposed files, ingests OpenAPI documents,
checks authentication and sessions, runs the detector catalogue, verifies each
finding with a second request, exploits the strongest ones when allowed, records
facts with provenance, and calls `goal.prove` before finishing.

* 23 tools with schemas, caps and timeouts
* deterministic planner offline, schema-checked LLM planner with a heuristic fallback
* scope, red-line, risk and approval gates that cannot be widened by the model
* asset graph with coverage, facts with provenance, hash-chained evidence
* adaptive mode: per-endpoint baselines, Bayesian hypotheses, UCB/Thompson bandit,
  cross-run priors scoped to the target
* playbooks, resume from saved state, run diffs, Prometheus metrics, self-audit
* SARIF, HTML, JUnit and Markdown reports from the same run

Documentation: [`docs/agent.md`](docs/agent.md),
[`docs/agent-safety.md`](docs/agent-safety.md),
[`docs/agent-runbook.md`](docs/agent-runbook.md),
[`docs/llm.md`](docs/llm.md),
[`docs/agent-adaptive.md`](docs/agent-adaptive.md). Skills live in [`skills/`](skills).

## Safety model

Every active technique needs an authorization document. Create one with the engagement
name, the client, the operator and the person who approved the work:

```bash
candix authorize --engagement q4-external --client acme \
  --operator ana --by "security manager" \
  --include app.acme.test:443 --include 10.20.0.0/24 --allow-exploit
```

The resulting JSON is passed to scans with `--engagement FILE`. Scope is enforced on
every request; anything outside the document is refused before a socket is opened.
`--authorized NAME` exists for targets you own personally; use it deliberately.

The bundled lab is a deliberately vulnerable application for testing Candix itself:

```bash
candix lab --scan
```

## Quick start

```bash
candix scan https://target.test/ --engagement engagement.json --formats html,json,sarif
candix exploit https://target.test/ --engagement engagement.json --max-proofs 3
candix report scan.json --formats junit,notebook,slides,tracker,badge --out reports/
candix export scan.json --out exports/ --tracker --junit --replay --siem cef
```

Exit codes are stable for pipelines: `0` clean, `10` findings at or above the threshold,
`1` error, `2` usage, `130` interrupted.

## Commands

| Command | Purpose |
|---|---|
| `scan` | reconnaissance, detection and reporting |
| `exploit` | detection plus proof-of-impact techniques |
| `report` | re-render reports from a saved scan JSON |
| `export` | remediation tracker, JUnit XML, notebook, slides and replay scripts |
| `authorize` | create the authorization and scope document |
| `detectors` | list detectors, severities and coverage |
| `payloads` | browse the payload catalogue |
| `playbooks` | verification steps per vulnerability class |
| `fuzz` | mutation fuzzing with anomaly scoring |
| `compare` | diff two scans to find new and resolved findings |
| `api` | HTTP API for CI pipelines |
| `notify` | send results to chat, ticketing and SIEM integrations |
| `shell` | interactive shell with ad-hoc request replay |
| `tui` | terminal dashboard |
| `lab` | run the vulnerable lab application |
| `doctor` | environment and configuration checks |

## Reports

`json`, `jsonl`, `html`, `markdown`, `sarif`, `csv`, `summary`, `junit`, `notebook`,
`slides`, `tracker` and `badge` are rendered from the same report model, so every format
agrees on counts, scores and evidence hashes. Bundles include a manifest with per-file
SHA-256 digests and an optional zip archive.

## Integrations and API

`webhook`, `slack`, `teams`, `pagerduty`, `discord`, `mattermost`, `jira`, `github`,
`gitlab`, `servicenow` and `defectdojo` are supported for delivery, with `cef`, `leef`,
`syslog` and `ndjson` SIEM formats. The API accepts scans asynchronously, exposes job
status and progress events, and serves reports; `GET /health`, `/version` and `/detectors`
are unauthenticated, everything else requires the bearer token from `CANDIX_API_TOKEN`.

## Development

```bash
python -m pytest -q tests
```

The package has no runtime dependencies; tests cover scoring, scope enforcement,
report rendering, authentication helpers, checkpoints and the API schema.
