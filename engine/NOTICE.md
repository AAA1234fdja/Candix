# Engine archive — provenance and licence

This directory is an **archived Go/React engine** kept as reference material for
Candix. It is a **renamed fork of ARTEX** (not a dependency).

## Provenance

| | |
| --- | --- |
| Original repository | `https://github.com/BaaRai/ARTEX.git` (fork of `https://github.com/Autumn-27/ARTEX`) |
| Archived commit | `6337341602be6aa5860b1e83138f03bdd0b78f71` (2026-11-17) |
| Commit subject | `Merge pull request #295 from BaaRai/feat-keenable-wiring` |
| Module path (original) | `github.com/Autumn-27/artex` |
| Module path (archived) | `github.com/AAA1234fdja/candix/engine` |
| Dependency `norma` | `https://github.com/BaaRai/Norma` (fork of `https://github.com/Autumn-27/norma`) — see `go.mod` |
| License | GNU Affero General Public License v3.0 — full text in `LICENSE` |
| Files | ~800 tracked files (Go, React, config, scripts) — see `go.mod` / `web/` |

The Go module path was rewritten from `github.com/Autumn-27/artex` to
`github.com/AAA1234fdja/candix/engine` to make the archive self-consistent
(233 Go files updated, 0 upstream paths retained). The `norma` dependency was
normalised from `github.com/Autumn-27/norma` (with a local `replace` to
`BaaRai/Norma`) to a direct `github.com/BaaRai/Norma` requirement so that
`go.mod` and `go.sum` share the same provenance and `go mod tidy` succeeds
without network access to a redirect.

If you need to verify the original ARTEX source, see the reference mirror
described in `docs/vendor-artex.md` on the `main` branch (`vendor/artex-reference/`
with `MANIFEST.json` and SHA-256 per file) or fetch the commit above directly:

```bash
git clone https://github.com/BaaRai/ARTEX.git /tmp/artex
git -C /tmp/artex checkout 6337341602be6aa5860b1e83138f03bdd0b78f71
```

## What this archive is — and is not

* **What it is**: the source of the ideas Candix's Python layer re-implements
  (pre-tool-use gate, argv/target normalisation, egress governor, budget tree,
  data envelopes). See `docs/engine.md` for the mapping table.
* **What it is not**: a live backend, a package dependency, or part of a Candix
  release. `pyproject.toml` excludes `engine*` from the wheel, Candix never
  imports it, and CI does not build it.

## Licensing consequence — read before shipping

ARTEX and this archive are **AGPL-3.0**; Candix itself is **MIT**
(`pyproject.toml`). Renaming a fork does not change its licence: distributing
these files — in any directory, under any name — makes the distribution
subject to the AGPL.

* Keeping this archive in the repository is fine for private study and for a
  repository that is itself AGPL-compatible.
* **Do not ship this directory inside a distributed Candix artifact** (wheel,
  container image, release tarball, client hand-off) under MIT terms. Either
  drop `engine/` from the artifact (the packaging exclude already does this),
  keep the mirror in a separate AGPL repository consumed as a submodule, or
  relicense the whole distribution.
* If your fork keeps both `vendor/artex-reference/` (verbatim mirror from
  `main`) **and** `engine/` (this renamed archive), you have two copies of the
  same AGPL tree under two attribution regimes — deduplicate before merging
  to avoid ~9 MB of redundant AGPL content with conflicting `NOTICE`/`README`
  claims.

## Upstream links

* ARTEX: https://github.com/BaaRai/ARTEX (fork of https://github.com/Autumn-27/ARTEX)
* Norma (engine dependency): https://github.com/BaaRai/Norma
* Candix Python re-implementation: `candix/agent/intercept.py`, `candix/agent/guard.py`, etc. (see `docs/engine.md`)
