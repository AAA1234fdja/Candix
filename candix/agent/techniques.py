"""Which technique covers which weakness, and what the run left untested."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.agent.knowledge import lookup, normalise


@dataclass(frozen=True)
class Technique:
    key: str
    name: str
    matrix: str
    tactic: str
    tools: tuple[str, ...]
    categories: tuple[str, ...]
    active: bool = False
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "matrix": self.matrix,
            "tactic": self.tactic,
            "tools": list(self.tools),
            "categories": list(self.categories),
            "active": self.active,
        }


APPLICABLE: tuple[Technique, ...] = (
    Technique(
        key="T1595.002",
        name="Active scanning: vulnerability scanning",
        matrix="reconnaissance",
        tactic="recon",
        tools=("detect.run", "fuzz.run"),
        categories=("xss", "sqli", "ssrf", "lfi", "open_redirect", "xxe"),
        active=True,
        notes="the detector catalogue plus a bounded fuzz campaign",
    ),
    Technique(
        key="T1595.001",
        name="Active scanning: scanning IP blocks",
        matrix="reconnaissance",
        tactic="recon",
        tools=("recon.fingerprint", "http.batch"),
        categories=(),
    ),
    Technique(
        key="T1590.005",
        name="Gather victim network information: IP addresses",
        matrix="reconnaissance",
        tactic="recon",
        tools=("recon.crawl", "recon.fingerprint"),
        categories=(),
    ),
    Technique(
        key="T1592.004",
        name="Gather victim host information: client configurations",
        matrix="reconnaissance",
        tactic="recon",
        tools=("recon.fingerprint", "web.probe"),
        categories=("cors",),
    ),
    Technique(
        key="T1594",
        name="Search victim-owned websites",
        matrix="reconnaissance",
        tactic="recon",
        tools=("recon.crawl", "api.spec", "graphql.query", "web.probe"),
        categories=("exposed_secret", "graphql_introspection"),
        active=True,
    ),
    Technique(
        key="T1190",
        name="Exploit public-facing application",
        matrix="initial-access",
        tactic="exploit",
        tools=("exploit.run", "fuzz.run"),
        categories=("sqli", "rce", "lfi", "ssrf", "xxe"),
        active=True,
        notes="only with exploitation enabled and an approved engagement",
    ),
    Technique(
        key="T1078",
        name="Valid accounts",
        matrix="initial-access",
        tactic="detect",
        tools=("auth.flow", "jwt.inspect", "oauth.flow"),
        categories=("jwt", "csrf"),
    ),
    Technique(
        key="T1552.001",
        name="Unsecured credentials in files",
        matrix="credential-access",
        tactic="recon",
        tools=("web.probe",),
        categories=("exposed_secret",),
        active=True,
    ),
    Technique(
        key="T1539",
        name="Steal web session cookie",
        matrix="credential-access",
        tactic="detect",
        tools=("auth.flow", "jwt.inspect"),
        categories=("xss", "jwt"),
    ),
    Technique(
        key="T1087",
        name="Account discovery",
        matrix="discovery",
        tactic="detect",
        tools=("api.spec", "http.batch"),
        categories=("idor",),
    ),
    Technique(
        key="T1213",
        name="Data from information repositories",
        matrix="collection",
        tactic="detect",
        tools=("detect.run",),
        categories=("idor", "exposed_secret"),
    ),
)


def techniques() -> list[Technique]:
    return sorted(APPLICABLE, key=lambda item: (item.matrix, item.key))


def by_category(category: str) -> list[Technique]:
    key = normalise(category)
    if not key:
        return []
    return [item for item in APPLICABLE if key in item.categories]


def by_tool(tool: str) -> list[Technique]:
    return [item for item in APPLICABLE if tool in item.tools]


def by_tactic(tactic: str) -> list[Technique]:
    return [item for item in APPLICABLE if item.tactic == tactic]


def active_techniques(*, allow_exploit: bool = False) -> list[Technique]:
    return [item for item in APPLICABLE if item.active and (allow_exploit or "exploit.run" not in item.tools)]


def coverage_matrix(tools_used: Iterable[str]) -> dict[str, list[str]]:
    used = set(tools_used)
    return {item.key: [tool for tool in item.tools if tool in used] for item in APPLICABLE}


def untested(techniques_run: Iterable[str]) -> list[Technique]:
    run = set(techniques_run)
    return [item for item in APPLICABLE if item.key not in run]


def infer_run(tools_used: Iterable[str]) -> set[str]:
    used = set(tools_used)
    return {item.key for item in APPLICABLE if used & set(item.tools)}


def gaps(tools_used: Iterable[str], *, allow_exploit: bool = False) -> list[Technique]:
    tested = infer_run(tools_used)
    return [item for item in APPLICABLE if item.key not in tested and (allow_exploit or "exploit.run" not in item.tools)]


def coverage_ratio(tools_used: Iterable[str]) -> float:
    tested = infer_run(tools_used)
    return round(len(tested) / len(APPLICABLE), 3) if APPLICABLE else 0.0


def tool_coverage() -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in APPLICABLE:
        for tool in item.tools:
            counts[tool] = counts.get(tool, 0) + 1
    return dict(sorted(counts.items()))


def for_findings(findings: Iterable[dict[str, Any]]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for finding in findings:
        category = normalise(str(finding.get("category", "") or finding.get("title", "")))
        if not category:
            continue
        mapping[category] = [item.key for item in by_category(category)]
    return mapping


def describe(finding: dict[str, Any]) -> str:
    category = str(finding.get("category", "") or "")
    items = by_category(category)
    if not items:
        return "no mapped technique"
    return "; ".join(f"{item.key} {item.name}" for item in items)


def table(tools_used: Iterable[str] = ()) -> str:
    used = set(tools_used)
    lines = ["| technique | matrix | tactic | tools | tested |", "| --- | --- | --- | --- | --- |"]
    for item in techniques():
        state = "yes" if used & set(item.tools) else ("n/a" if not used else "no")
        lines.append(f"| {item.key} {item.name} | {item.matrix} | {item.tactic} | {', '.join(item.tools)} | {state} |")
    return "\n".join(lines) + "\n"


def recommendations(tools_used: Iterable[str], *, limit: int = 5, allow_exploit: bool = False) -> list[str]:
    hints: list[str] = []
    for item in gaps(tools_used, allow_exploit=allow_exploit)[:limit]:
        tool = item.tools[0]
        hints.append(f"run {tool} to cover {item.key} ({item.name})")
    if not tools_used:
        hints = ["no technique has run yet: start with recon.crawl and web.probe"]
    return hints


def categories_covered(tools_used: Iterable[str]) -> list[str]:
    used = set(tools_used)
    found: set[str] = set()
    for item in APPLICABLE:
        if used & set(item.tools):
            found.update(item.categories)
    return sorted(found)


def knowledge_gap(tools_used: Iterable[str]) -> list[str]:
    """Categories a technique could reach but where no detector exists yet."""

    reachable = set(categories_covered(tools_used))
    return sorted(name for name in reachable if lookup(name) is None)


@dataclass
class TechniqueReport:
    tools_used: list[str] = field(default_factory=list)
    tested: list[str] = field(default_factory=list)
    open_gaps: list[str] = field(default_factory=list)
    ratio: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"tools": self.tools_used, "tested": self.tested, "gaps": self.open_gaps, "ratio": self.ratio}

    def markdown(self) -> str:
        lines = ["## ATT&CK coverage", "", f"Coverage: {self.ratio:.0%} of {len(APPLICABLE)} applicable techniques", ""]
        lines.append(f"- tested: {', '.join(self.tested) or 'none'}")
        lines.append(f"- open: {', '.join(self.open_gaps) or 'none'}")
        lines.append("")
        return "\n".join(lines)


def report(tools_used: Iterable[str], *, allow_exploit: bool = False) -> TechniqueReport:
    used = list(tools_used)
    tested = sorted(infer_run(used))
    return TechniqueReport(
        tools_used=used,
        tested=tested,
        open_gaps=[item.key for item in gaps(used, allow_exploit=allow_exploit)],
        ratio=coverage_ratio(used),
    )
