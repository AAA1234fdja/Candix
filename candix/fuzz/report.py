"""Rendering fuzzing results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from candix.cli import output as out
from candix.fuzz.model import FuzzResult


def render_fuzz_summary(result: FuzzResult) -> str:
    counts = result.counts()
    lines = [
        out.rule("fuzz results"),
        out.kv_table(
            [
                ("scan id", result.scan_id),
                ("strategy", result.strategy),
                ("seed", result.seed),
                ("iterations", f"{result.iterations} planned · {len(result.cases)} sent"),
                ("parameters", result.stats.get("parameters", 0)),
                ("signals", len(result.signals)),
                ("errors", result.errors),
                ("duration", result.summary()["duration_human"]),
                ("findings", out.counts_bar(counts)),
            ],
            indent=2,
        ),
    ]
    families = result.stats.get("mutation_families") or {}
    if families:
        lines.append("")
        lines.append(out.paint("  mutation mix", "grey"))
        for family, count in sorted(families.items(), key=lambda pair: -pair[1]):
            lines.append(f"    {family.ljust(12)} {count}")
    interesting = [observation for observation in result.observations if observation.interesting]
    if interesting:
        lines.append("")
        lines.append(out.rule("top signals"))
        rows = []
        for observation in sorted(interesting, key=lambda item: -(item.signal.score if item.signal else 0))[:15]:
            signal = observation.signal
            rows.append([
                signal.kind,
                f"{signal.score:.2f}",
                f"{observation.case.method} {observation.case.url}"[:70],
                observation.case.parameter,
                observation.case.family,
            ])
        lines.append(out.table(["SIGNAL", "SCORE", "REQUEST", "PARAM", "FAMILY"], rows))
    if result.findings:
        lines.append("")
        lines.append(out.rule("findings"))
        for finding in result.findings[:20]:
            lines.append(out.finding_block(finding))
    if result.corpus_dir:
        lines.append("")
        lines.append(out.kv_table([("corpus", result.corpus_dir)], indent=2))
    return "\n".join(lines)


def fuzz_markdown(result: FuzzResult) -> str:
    summary = result.summary()
    lines = [
        "# Fuzzing report",
        "",
        f"- **scan:** `{result.scan_id}`",
        f"- **strategy:** {result.strategy} (seed {result.seed})",
        f"- **requests:** {len(result.cases)} of {result.iterations} planned",
        f"- **duration:** {summary['duration_human']}",
        f"- **signals:** {len(result.signals)} · **findings:** {len(result.findings)} · **errors:** {result.errors}",
        "",
        "## Mutation coverage",
        "",
        "| Family | Cases |",
        "|---|---|",
    ]
    for family, count in sorted((result.stats.get("mutation_families") or {}).items(), key=lambda pair: -pair[1]):
        lines.append(f"| {family} | {count} |")
    lines.append("")
    lines.append("## Signals")
    lines.append("")
    if not result.signals:
        lines.append("_No anomalous responses._")
    for observation in result.observations:
        if not observation.signal:
            continue
        signal = observation.signal
        lines.append(f"### {signal.kind} · score {signal.score:.2f}")
        lines.append("")
        lines.append(f"- **request:** `{observation.case.method} {observation.case.url}`")
        lines.append(f"- **parameter:** `{observation.case.parameter}` ({observation.case.location})")
        lines.append(f"- **payload:** `{observation.case.value[:160]}`")
        lines.append(f"- **status:** {observation.status} (baseline {observation.baseline_status})")
        for reason in signal.reasons:
            lines.append(f"- {reason}")
        lines.append("")
    if result.findings:
        lines.append("## Findings")
        lines.append("")
        from candix.report.markdown import render_finding_markdown

        for finding in result.findings:
            lines.append(render_finding_markdown(finding, include_evidence=False))
            lines.append("")
    return "\n".join(lines)


def write_fuzz_outputs(result: FuzzResult, directory: str | Path, *, formats: tuple[str, ...] = ("json", "markdown")) -> dict[str, str]:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    if "json" in formats:
        path = target / f"fuzz-{result.scan_id}.json"
        path.write_text(result.to_json(), encoding="utf-8")
        written["json"] = str(path)
    if "markdown" in formats:
        path = target / f"fuzz-{result.scan_id}.md"
        path.write_text(fuzz_markdown(result), encoding="utf-8")
        written["markdown"] = str(path)
    return written


def load_fuzz_result(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
