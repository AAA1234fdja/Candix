# ARTEX reference copy (AGPL-3.0)

This directory is a **verbatim source mirror of ARTEX**, kept as reference
material for Candix. Nothing here is imported, packaged or executed: the Python
package never references `vendor/`, and `pyproject.toml` excludes it.

## Provenance

| | |
| --- | --- |
| Repository | `https://github.com/BaaRai/ARTEX.git` (fork of `https://github.com/Autumn-27/ARTEX`) |
| Commit | `6337341602be6aa5860b1e83138f03bdd0b78f71` |
| Commit date | 2026-11-17 17:39:38 +0100 |
| Commit subject | `Merge pull request #295 from BaaRai/feat-keenable-wiring` |
| License | GNU Affero General Public License v3.0 — full text in `LICENSE` |
| Copied | **838 of 855 tracked files (98.01%)**, 8.88 MB, none edited |
| Skipped | 17 binary assets only (15 PNG screenshots/icons, 1 SVG, 1 CSS-sprite set — see `MANIFEST.json`) |
| Integrity | [`MANIFEST.json`](MANIFEST.json) lists every copied file with size and SHA-256 |

The selection rule is mechanical, not editorial: *everything that is source or
documentation is copied; only images and fonts are left out*. `MANIFEST.json`
records the upstream file count, the copy ratio, the per-extension breakdown and
the exact list of skipped files, so the mirror can be reproduced and audited.

| extension | files | | extension | files |
| --- | --- | --- | --- | --- |
| `.go` | 528 | | `.json` | 13 |
| `.tsx` | 154 | | `.sh` | 12 |
| `.ts` | 37 | | `.py` | 12 |
| `.md` | 36 | | `.sql` / `.mjs` / `.yml` / `.css` / `.js` | 29 |
| no extension / other | 15 | | | |

Verification, from the repository root:

```bash
python3 - <<'PY'
import hashlib, json, pathlib
root = pathlib.Path("vendor/artex-reference")
manifest = json.loads((root / "MANIFEST.json").read_text())
bad = [item["path"] for item in manifest["files"]
       if hashlib.sha256((root / item["path"]).read_bytes()).hexdigest() != item["sha256"]]
print(len(manifest["files"]), "files,", len(bad), "mismatches")
PY
```

## Where to start reading

A 838-file mirror is not a reading list. These are the parts worth imitating
first — the code that decides *what the agent may do*, where a mistake becomes an
incident rather than a bad report:

| file | what it decides |
| --- | --- |
| `guard/guard.go` | pre-tool-use hook: allow/block, one audit entry per call, failure attribution |
| `intercept/risk.go` | deterministic 0..100 risk score with reasons, per tool shape |
| `intercept/alwaysallow_denylist.go` | programs an argv allow rule may never name (interpreters, launchers, package managers) |
| `intercept/argv.go` | shell parsing, argv arity, prefix derivation and matching |
| `intercept/target.go`, `intercept/target_dial.go` | target normalisation (IDNA, IPv4-mapped, decimal/hex/octal, CIDR) and dial-time enforcement |
| `egress/egress.go`, `egress/pace.go` | the governor every platform-owned request passes through: buckets, jitter, per-host concurrency, backoff |
| `agent/budget.go` | hierarchical task → intent → round budgets with a wrap-up reserve |
| `agent/untrusted_prompt.go`, `agent/data_envelope.go` | injection-defence prompt tails a DB override cannot drop, and provenance envelopes |
| `agent/planner.go`, `agent/worker.go`, `agent/toolcatalog.go` | the planner/worker split and how tools are described to the model |
| `evidence/store.go` | evidence persistence and integrity |

The rest of the mirror is volume: tool adapters (`agent/tools.go`, 108 KB), the
HTTP proxy, DB migrations, the React UI, the integrations. Useful as a reference
for behaviour, not as a source of design decisions.

## Candix equivalents

| ARTEX | Candix |
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

The Python side reimplements the *behaviour*; it does not copy ARTEX text,
identifiers or structure.

## Licensing consequence — read before shipping

ARTEX is **AGPL-3.0**; Candix is **MIT** (`pyproject.toml`). Copyleft is not
compatible with MIT for a combined distributed work:

* Keeping this mirror in the repository is fine for private study, and for a
  repository that is itself AGPL-compatible.
* **Do not ship this directory inside a distributed Candix artifact** (wheel,
  container image, release tarball, client hand-off) under MIT terms. Either
  drop `vendor/artex-reference/` from the artifact, keep the mirror in a
  separate AGPL repository consumed as a submodule, or relicense the whole
  distribution.
* `pyproject.toml` already excludes `vendor*` from the package, and
  `tests/test_vendor_reference.py` fails if the package imports the mirror, if
  the AGPL text is missing, or if any manifest hash no longer matches.
