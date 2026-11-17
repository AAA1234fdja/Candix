"""Methodology coverage: what was tested, not just what was found.

A report that lists three findings says nothing about the twenty areas nobody
looked at. The scorecard records, per category, whether the run had a relevant
tool, whether it produced evidence, and whether the asset graph had anything to
test in the first place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from candix.core.severity import Severity

STATUS_ORDER = {"covered": 0, "partial": 1, "gap": 2, "untested": 3}


@dataclass
class Check:
    name: str
    ok: Callable[[dict[str, Any]], bool]
    detail: str = ""


@dataclass
class Category:
    name: str
    weight: float
    tools: tuple[str, ...]
    categories: tuple[str, ...]
    checks: list[Check] = field(default_factory=list)
    description: str = ""


def _has(context: dict[str, Any], marker: str) -> bool:
    return marker in (context.get("tools") or set())


def _findings_with(context: dict[str, Any], *categories: str) -> list[dict[str, Any]]:
    wanted = {item.lower() for item in categories}
    return [
        finding
        for finding in context.get("findings", [])
        if str(finding.get("category", "")).lower() in wanted
    ]


def _endpoints(context: dict[str, Any]) -> int:
    return int((context.get("coverage") or {}).get("endpoints", 0) or 0)


CATEGORIES: tuple[Category, ...] = (
    Category(
        name="reconnaissance",
        weight=1.0,
        tools=("recon.crawl", "recon.fingerprint", "web.probe"),
        categories=("exposure",),
        description="Surface mapping: crawl, fingerprint, content discovery.",
        checks=[
            Check("crawl executed", lambda ctx: _has(ctx, "recon.crawl")),
            Check("technology fingerprinted", lambda ctx: _has(ctx, "recon.fingerprint")),
            Check("endpoints discovered", lambda ctx: _endpoints(ctx) > 0),
            Check("content discovery ran", lambda ctx: _has(ctx, "web.probe")),
        ],
    ),
    Category(
        name="authentication",
        weight=1.2,
        tools=("auth.flow", "jwt.inspect", "detect.run"),
        categories=("authentication", "session"),
        description="Login handling, session rotation, token validation.",
        checks=[
            Check("login flow exercised", lambda ctx: _has(ctx, "auth.flow")),
            Check("token handling reviewed", lambda ctx: _has(ctx, "jwt.inspect")),
            Check("auth findings recorded", lambda ctx: bool(_findings_with(ctx, "authentication", "session"))),
        ],
    ),
    Category(
        name="authorization",
        weight=1.3,
        tools=("detect.run", "http.request", "exploit.run"),
        categories=("authorization", "idor", "access-control"),
        description="Object and function level access control.",
        checks=[
            Check("detector catalogue ran", lambda ctx: _has(ctx, "detect.run")),
            Check("authorization findings recorded", lambda ctx: bool(_findings_with(ctx, "authorization", "idor", "access-control"))),
            Check("finding verified with a second request", lambda ctx: any(bool(item.get("verified")) for item in ctx.get("findings", []))),
        ],
    ),
    Category(
        name="injection",
        weight=1.3,
        tools=("detect.run", "exploit.run", "fuzz.run"),
        categories=("injection", "sqli", "xss", "ssrf", "template", "command"),
        description="Input handling across query, body and headers.",
        checks=[
            Check("parameters discovered", lambda ctx: int((ctx.get("coverage") or {}).get("parameters", 0) or 0) > 0),
            Check("injection findings recorded", lambda ctx: bool(_findings_with(ctx, "injection", "sqli", "xss", "ssrf", "template", "command"))),
        ],
    ),
    Category(
        name="exposure",
        weight=1.0,
        tools=("web.probe", "api.spec", "detect.run"),
        categories=("exposure",),
        description="Files, metadata and documentation that should not be public.",
        checks=[
            Check("dotfiles probed", lambda ctx: _has(ctx, "web.probe")),
            Check("API description checked", lambda ctx: _has(ctx, "api.spec")),
            Check("exposure findings recorded", lambda ctx: bool(_findings_with(ctx, "exposure"))),
        ],
    ),
    Category(
        name="api",
        weight=1.1,
        tools=("api.spec", "graphql.query", "http.request"),
        categories=("api", "graphql"),
        description="Documented and undocumented API surface.",
        checks=[
            Check("OpenAPI ingested", lambda ctx: _has(ctx, "api.spec")),
            Check("GraphQL introspected", lambda ctx: _has(ctx, "graphql.query")),
            Check("API endpoints probed", lambda ctx: _has(ctx, "http.request")),
        ],
    ),
    Category(
        name="transport",
        weight=0.8,
        tools=("detect.run", "http.request"),
        categories=("transport", "headers", "tls"),
        description="TLS, security headers and cookie flags.",
        checks=[
            Check("headers reviewed", lambda ctx: _has(ctx, "detect.run")),
            Check("cookie flags inspected", lambda ctx: _has(ctx, "auth.flow")),
        ],
    ),
    Category(
        name="verification",
        weight=1.0,
        tools=("http.request", "exploit.run", "goal.prove"),
        categories=(),
        description="Every claim reproduced, every proof anchored.",
        checks=[
            Check("findings re-requested", lambda ctx: bool(ctx.get("verified"))),
            Check("proof attempted", lambda ctx: bool(ctx.get("proofs"))),
            Check("evidence chain built", lambda ctx: int(ctx.get("evidence", 0)) > 0),
        ],
    ),
)


@dataclass
class CategoryScore:
    name: str
    status: str
    ratio: float
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "ratio": round(self.ratio, 2),
            "passed": self.passed,
            "failed": self.failed,
            "weight": self.weight,
        }


@dataclass
class Scorecard:
    categories: list[CategoryScore] = field(default_factory=list)
    score: float = 0.0
    grade: str = "PENDING"

    def gaps(self) -> list[CategoryScore]:
        return [item for item in self.categories if item.status in {"gap", "untested"}]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "grade": self.grade,
            "categories": [item.to_dict() for item in self.categories],
            "gaps": [item.name for item in self.gaps()],
            "summary": self.summary(),
        }

    def summary(self) -> str:
        covered = sum(1 for item in self.categories if item.status == "covered")
        return f"{self.score:.0f}/100 ({self.grade}), {covered}/{len(self.categories)} categories covered"

    def markdown(self) -> str:
        lines = ["| Category | Status | Score | Gaps |", "| --- | --- | --- | --- |"]
        for item in sorted(self.categories, key=lambda entry: STATUS_ORDER.get(entry.status, 9)):
            gaps = ", ".join(item.failed[:3]) or "-"
            lines.append(f"| {item.name} | {item.status} | {item.ratio * 100:.0f}% | {gaps} |")
        return "\n".join(lines) + "\n"


def build(
    *,
    findings: Iterable[dict[str, Any]] = (),
    assets: Any = None,
    attempted_tools: Iterable[str] = (),
    proofs: int = 0,
    evidence: int = 0,
    verified: int = 0,
) -> Scorecard:
    findings = list(findings)
    coverage = assets.coverage() if assets is not None else {}
    context = {
        "findings": findings,
        "coverage": coverage,
        "tools": set(attempted_tools),
        "proofs": proofs,
        "evidence": evidence,
        "verified": verified,
    }
    scorecard = Scorecard()
    weighted = 0.0
    total_weight = 0.0
    for category in CATEGORIES:
        passed: list[str] = []
        failed: list[str] = []
        for check in category.checks:
            try:
                ok = bool(check.ok(context))
            except Exception:
                ok = False
            (passed if ok else failed).append(check.name)
        ratio = len(passed) / len(category.checks) if category.checks else 0.0
        if ratio >= 0.99:
            status = "covered"
        elif ratio > 0:
            status = "partial"
        elif any(tool in context["tools"] for tool in category.tools):
            status = "gap"
        else:
            status = "untested"
        scorecard.categories.append(
            CategoryScore(
                name=category.name,
                status=status,
                ratio=ratio,
                passed=passed,
                failed=failed,
                weight=category.weight,
            )
        )
        weighted += ratio * category.weight
        total_weight += category.weight
    scorecard.score = 100.0 * weighted / total_weight if total_weight else 0.0
    scorecard.grade = _grade(scorecard.score)
    return scorecard


def _grade(score: float) -> str:
    for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (55, "D"), (40, "E")):
        if score >= threshold:
            return grade
    return "F"


def from_result(result: Any, assets: Any = None, *, evidence: int = 0) -> Scorecard:
    attempted = {getattr(intent, "tool", "") for intent in getattr(result, "intents", []) if getattr(intent, "tool", "")}
    findings = list(getattr(result, "findings", []))
    return build(
        findings=findings,
        assets=assets,
        attempted_tools=attempted,
        proofs=len(getattr(result, "proofs", [])),
        evidence=evidence,
        verified=sum(1 for finding in findings if finding.get("verified") or finding.get("exploited")),
    )


def critical_gaps(scorecard: Scorecard, limit: int = 3) -> list[str]:
    """The next three things a follow-up run should test."""

    hints: list[str] = []
    for item in scorecard.gaps()[:limit]:
        category = next((category for category in CATEGORIES if category.name == item.name), None)
        if category is None:
            continue
        tool = category.tools[0] if category.tools else "http.request"
        hints.append(f"{item.name}: run {tool} ({', '.join(item.failed[:2])})")
    return hints
