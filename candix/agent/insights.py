"""What the run's own telemetry says about how to run it better."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.agent.models import Intent


@dataclass
class Insight:
    kind: str
    text: str
    weight: float = 0.5
    metric: str = ""
    value: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "text": self.text, "weight": self.weight, "metric": self.metric, "value": self.value}


@dataclass
class ToolStat:
    tool: str
    calls: int = 0
    errors: int = 0
    seconds: float = 0.0
    findings: int = 0

    @property
    def error_rate(self) -> float:
        return self.errors / self.calls if self.calls else 0.0

    @property
    def average_seconds(self) -> float:
        return self.seconds / self.calls if self.calls else 0.0

    @property
    def findings_per_call(self) -> float:
        return self.findings / self.calls if self.calls else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "calls": self.calls,
            "errors": self.errors,
            "seconds": round(self.seconds, 2),
            "average_seconds": round(self.average_seconds, 2),
            "error_rate": round(self.error_rate, 2),
            "findings": self.findings,
        }


@dataclass
class Report:
    tools: list[ToolStat] = field(default_factory=list)
    insights: list[Insight] = field(default_factory=list)
    duration: float = 0.0
    tool_calls: int = 0
    turns: int = 0

    def top(self, limit: int = 3) -> list[Insight]:
        return sorted(self.insights, key=lambda item: -item.weight)[:limit]

    def to_dict(self) -> dict[str, Any]:
        return {
            "duration": round(self.duration, 2),
            "tool_calls": self.tool_calls,
            "turns": self.turns,
            "tools": [tool.to_dict() for tool in self.tools],
            "insights": [item.to_dict() for item in self.insights],
        }

    def markdown(self) -> str:
        lines = ["| Tool | Calls | Errors | Avg s | Findings |", "| --- | --- | --- | --- | --- |"]
        for tool in sorted(self.tools, key=lambda item: -item.calls)[:12]:
            lines.append(
                f"| {tool.tool} | {tool.calls} | {tool.errors} | {tool.average_seconds:.1f} | {tool.findings} |"
            )
        if self.insights:
            lines.extend(["", "Insights:", ""])
            lines.extend(f"- {item.text}" for item in self.top(6))
        return "\n".join(lines) + "\n"

    def summary(self) -> str:
        slowest = max(self.tools, key=lambda item: item.seconds, default=None)
        text = f"{self.tool_calls} tool call(s) over {self.turns} turn(s) in {self.duration:.0f}s"
        if slowest is not None:
            text += f"; slowest {slowest.tool} ({slowest.seconds:.0f}s)"
        return text


def collect(result: Any, telemetry: Any = None, *, budget: Any = None) -> Report:
    report = Report()
    stats: dict[str, ToolStat] = {}
    findings_by_tool: dict[str, int] = {}
    for intent in getattr(result, "intents", []) or []:
        tool = str(getattr(intent, "tool", "") or "unknown")
        stat = stats.setdefault(tool, ToolStat(tool))
        stat.calls += 1
        if getattr(intent.status, "value", str(intent.status)) == "failed":
            stat.errors += 1
        stat.seconds += float(getattr(intent, "duration", 0.0) or 0.0)
        findings_by_tool[tool] = findings_by_tool.get(tool, 0)
    for finding in getattr(result, "findings", []) or []:
        detector = str(finding.get("detector") or finding.get("tool") or "")
        for tool in stats:
            if detector and detector in tool:
                stats[tool].findings += 1
                break
    report.tools = list(stats.values())
    report.duration = float(getattr(result, "duration", 0.0) or 0.0)
    report.tool_calls = sum(stat.calls for stat in report.tools)
    report.turns = int(getattr(budget, "turns", 0) or 0) if budget is not None else 0

    report.insights = _insights(result, report, telemetry)
    return report


def _insights(result: Any, report: Report, telemetry: Any) -> list[Insight]:
    insights: list[Insight] = []
    stop_reason = str(getattr(result, "stop_reason", ""))
    if "turn" in stop_reason:
        insights.append(
            Insight(
                "budget",
                "The turn cap stopped the run before a proof; raise --turns or start from a narrower goal.",
                0.9,
                "stop_reason",
                1.0,
            )
        )
    if "time" in stop_reason:
        insights.append(Insight("budget", "The wall clock stopped the run; the slowest tool below is the reason.", 0.8))
    for tool in report.tools:
        if tool.error_rate >= 0.5 and tool.calls >= 2:
            insights.append(
                Insight(
                    "reliability",
                    f"{tool.tool} failed {tool.errors}/{tool.calls} time(s); check scope, arguments and caps before retrying.",
                    0.75,
                    tool.tool,
                    tool.error_rate,
                )
            )
        if tool.seconds >= 30:
            insights.append(
                Insight(
                    "performance",
                    f"{tool.tool} spent {tool.seconds:.0f}s; run it later or lower its work per call.",
                    0.6,
                    tool.tool,
                    tool.seconds,
                )
            )
        if tool.calls >= 4 and tool.findings == 0:
            insights.append(
                Insight(
                    "efficiency",
                    f"{tool.tool} ran {tool.calls} times without producing a finding; drop it from this playbook.",
                    0.5,
                    tool.tool,
                    tool.calls,
                )
            )
    findings = getattr(result, "findings", []) or []
    proofs = getattr(result, "proofs", []) or []
    if findings and not proofs:
        insights.append(
            Insight("proof", "Findings exist but no proof was captured; run exploit.run or record facts first.", 0.85)
        )
    if proofs and findings:
        unverified = [item for item in findings if not (item.get("verified") or item.get("exploited"))]
        if unverified:
            insights.append(
                Insight("verification", f"{len(unverified)} finding(s) were never re-requested; verify before reporting.", 0.7)
            )
    if telemetry is not None and hasattr(telemetry, "summary"):
        failures = 0
        try:
            counters = telemetry.snapshot().get("counters", {})
            failures = int(counters.get("worker.crashed", 0))
        except Exception:
            failures = 0
        if failures:
            insights.append(Insight("worker", f"The worker crashed {failures} time(s); inspect the journal for the trace.", 0.8))
    if not findings and report.tool_calls:
        insights.append(
            Insight("coverage", "No findings at all usually means the surface was empty or the detectors could not reach it.", 0.6)
        )
    return insights


def tuning(report: Report, limits: Any) -> dict[str, Any]:
    """Suggest budget changes from observed spend."""

    suggestions: dict[str, Any] = {}
    if limits is None:
        return suggestions
    if report.tool_calls and getattr(limits, "tool_calls", 0):
        ratio = report.tool_calls / max(1, limits.tool_calls)
        if ratio > 0.9:
            suggestions["tool_calls"] = int(limits.tool_calls * 1.5)
        elif ratio < 0.3:
            suggestions["tool_calls"] = max(20, int(limits.tool_calls * 0.7))
    slow = sum(tool.seconds for tool in report.tools)
    if slow and getattr(limits, "seconds", 0):
        if slow > limits.seconds * 0.8:
            suggestions["seconds"] = int(limits.seconds * 1.4)
    return suggestions


def export_markdown(report: Report) -> str:
    lines = ["# Run insights", "", report.summary(), "", report.markdown()]
    suggestions = report.top(5)
    if suggestions:
        lines.append("## What to change next")
        lines.append("")
        lines.extend(f"- {item.text}" for item in suggestions)
    return "\n".join(lines) + "\n"


def to_intents(report: Report, *, limit: int = 2) -> list[Intent]:
    """Turn strong insights into follow-up intents for the next run."""

    output: list[Intent] = []
    for insight in report.top(limit):
        if insight.kind == "proof":
            output.append(
                Intent("Capture a proof", phase="exploit", tool="exploit.run", arguments={"max_attempts": 2}, priority=0.9)
            )
        elif insight.kind == "verification":
            output.append(
                Intent("Verify the findings", phase="verify", tool="http.request", arguments={"note": "verification"}, priority=0.7)
            )
    return output


def compare(first: Report, second: Report) -> dict[str, Any]:
    """Diff two runs' tool profiles."""

    left = {tool.tool: tool for tool in first.tools}
    right = {tool.tool: tool for tool in second.tools}
    added = sorted(set(right) - set(left))
    removed = sorted(set(left) - set(right))
    slower = []
    for name in sorted(set(left) & set(right)):
        delta = right[name].average_seconds - left[name].average_seconds
        if abs(delta) >= 1.0:
            slower.append((name, round(delta, 2)))
    return {
        "added_tools": added,
        "removed_tools": removed,
        "duration_delta": round(second.duration - first.duration, 2),
        "calls_delta": second.tool_calls - first.tool_calls,
        "slower": slower,
    }


def bottlenecks(report: Report, *, limit: int = 3) -> list[ToolStat]:
    return sorted(report.tools, key=lambda item: -item.seconds)[:limit]


def unreliable(report: Report, *, threshold: float = 0.34) -> list[ToolStat]:
    return [tool for tool in report.tools if tool.error_rate >= threshold and tool.calls >= 2]


def productive(report: Report, *, threshold: float = 0.5) -> list[ToolStat]:
    return [tool for tool in report.tools if tool.findings_per_call >= threshold]


def iter_insights(report: Report, kind: str) -> Iterable[Insight]:
    return (item for item in report.insights if item.kind == kind)
