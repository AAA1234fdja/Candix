"""Report adapter — engine/report Markdown/PDF en Python."""

from __future__ import annotations

from datetime import datetime
from typing import Any


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}

def _nz(s: str, default: str) -> str:
    return s if s and s.strip() else default

class ReportEngine:
    def markdown(self, title: str = "", goal: str = "", findings: list[dict[str, Any]] | None = None, asset_counts: dict[str, int] | None = None, coverage: dict[str, Any] | None = None, generated_at: datetime | None = None) -> str:
        findings = findings or []
        asset_counts = asset_counts or {}
        generated_at = generated_at or datetime.utcnow()
        out: list[str] = []
        out.append(f"# Penetration Test Report — {_nz(title, 'Unnamed task')}")
        out.append("")
        out.append(f"- **Task goal**: {_nz(goal, '(unspecified)')}")
        out.append(f"- **Generated at**: {generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
        out.append("")
        out.append("## Summary")
        out.append("")
        out.append(f"- Confirmed findings: **{len(findings)}**")
        if asset_counts:
            parts = ", ".join(f"{k} {v}" for k, v in sorted(asset_counts.items()))
            out.append(f"- Assets: {parts}")
        out.append("")
        out.append("## Findings")
        out.append("")
        if not findings:
            out.append("_No vulnerabilities confirmed this time._")
            out.append("")
        else:
            sorted_findings = sorted(findings, key=lambda f: _SEV_RANK.get(str(f.get('severity', '')).lower(), 5))
            for i, f in enumerate(sorted_findings, 1):
                sev = str(f.get('severity', 'info')).upper()
                name = _nz(str(f.get('name', f.get('title', ''))), _nz(str(f.get('vulnclass', '')), 'Uncategorized'))
                summary = str(f.get('summary', f.get('description', '')))
                poc = f.get('poc', f.get('evidence', {}).get('poc', '')) if isinstance(f.get('evidence'), dict) else f.get('poc', '')
                out.append(f"### {i}. [{sev}] {name}")
                out.append("")
                if summary:
                    out.append(summary)
                    out.append("")
                if poc:
                    out.append("**PoC / Evidence:**")
                    out.append("")
                    out.append("```")
                    out.append(str(poc))
                    out.append("```")
                    out.append("")
        if coverage:
            out.append("## Coverage gaps")
            out.append("")
            out.append(f"- Ledger entries: {coverage.get('entries', 0)}, open gaps: {len(coverage.get('gaps', []))}")
            for g in (coverage.get('gaps') or [])[:200]:
                out.append(f"- {g}")
            out.append("")
        return "\n".join(out)

    def json_report(self, **kw: Any) -> dict[str, Any]:
        md = self.markdown(**kw)
        return {"markdown": md, "findings": kw.get("findings", []), "asset_counts": kw.get("asset_counts", {}), "generated_at": (kw.get("generated_at") or datetime.utcnow()).isoformat()}

    def quality_bullets(self, finding: dict[str, Any]) -> str:
        q = finding.get('quality', {})
        if not q:
            return ""
        lines = []
        for k in ("poe_level", "verification_state", "evidence_version"):
            if q.get(k):
                lines.append(f"- **{k}**: {q[k]}")
        return "\n".join(lines)
