# ARTEX reference copy (AGPL-3.0)

This directory contains **unmodified source files copied from ARTEX**, kept as
reference material for Candix. They are **not** part of the Python package, are
never imported by `candix`, and are not built or executed here.

## Provenance

| | |
| --- | --- |
| Repository | `https://github.com/BaaRai/ARTEX.git` (fork of `Autumn-27/ARTEX`) |
| Commit | `6337341602be6aa5860b1e83138f03bdd0b78f71` |
| Commit date | 2026-11-17 17:39:38 +0100 |
| Commit subject | `Merge pull request #295 from BaaRai/feat-keenable-wiring` |
| License | GNU Affero General Public License v3.0 — full text in `LICENSE` |
| Copied | 16 files, 4,262 lines, none edited |

Each file keeps its original package comment and, where present, its SPDX or
license header. `git diff --no-index` against the upstream commit shows no
changes.

## Why these files

Selection rule: the code that decides *what the agent is allowed to do* first,
then the parts of the agent loop that Candix has to imitate to behave the same
way. A tool registry of a hundred adapters is reproducible; a risk table that is
wrong is not recoverable after it damages a client.

### Safety boundary — highest risk

| file | what it decides |
| --- | --- |
| `guard/guard.go` | pre-tool-use hook: allow/block, audit entry per call, failure attribution |
| `intercept/risk.go` | deterministic 0..100 risk score with reasons, per tool shape |
| `intercept/alwaysallow_denylist.go` | programs an argv allow rule may never name (interpreters, launchers, package managers) |
| `intercept/argv.go` | shell parsing, argv prefix, arity table, prefix matching |
| `intercept/target.go` | target normalisation: host/port/CIDR, IDNA, IPv4-mapped, scheme default ports |
| `intercept/target_dial.go` | dial-time enforcement of the normalised target |
| `egress/egress.go` | the governor every platform-owned request passes through |
| `egress/pace.go` | pacing/noise profile plumbing for that governor |

### Agent core — the parts worth imitating

| file | what it does |
| --- | --- |
| `agent/budget.go` | hierarchical task → intent → round budgets with a wrap-up reserve |
| `agent/noise_profile.go` | the code-owned "low and slow" prompt block derived from the egress profile |
| `agent/untrusted_prompt.go` | injection-defence prompt tails that a DB override cannot drop |
| `agent/data_envelope.go` | provenance envelope around data the model reads |
| `agent/planner.go` | planner loop, state it is allowed to see, goal handling |
| `agent/worker.go` | worker loop, tool execution, write-back |
| `agent/toolcatalog.go` | how tools are described to the model |
| `evidence/store.go` | evidence persistence and integrity |

## Licensing consequence — read before shipping

ARTEX is **AGPL-3.0**; Candix is **MIT** (`pyproject.toml`). Copyleft is not
compatible with MIT for a combined distributed work:

* Keeping this directory in the repository is fine for private study and for a
  repository that is itself AGPL-compatible.
* **Do not ship this directory inside a distributed Candix artifact** (wheel,
  container, release tarball, client hand-off) under the MIT terms. Either drop
  `vendor/artex-reference/` from the artifact, keep it in a separate AGPL
  repository, or relicense the whole distribution.
* The Python implementation in `candix/agent/intercept.py` is an independent
  reimplementation of the *behaviour* described here, written for this codebase;
  it does not copy ARTEX text, identifiers or structure.

`tests/test_vendor_reference.py` enforces the mechanical part of this: the
package must not import from `vendor/`, the tree must carry the AGPL text, and
`NOTICE.md` must list every file that is present.
