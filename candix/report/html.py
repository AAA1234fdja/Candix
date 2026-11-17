"""Self-contained HTML report.

The output is a single file with inline CSS and JavaScript: no external fonts,
scripts or images, so it can be emailed, archived and opened offline without
leaking a request to a third party.
"""

from __future__ import annotations

import html as html_module
import json
from typing import Any, Iterable

from candix.core.clock import humanize_duration
from candix.core.severity import Severity
from candix.report.executive import build_executive_view
from candix.report.model import ReportModel

_CSS = """
:root {
  --bg: #0b1020; --panel: #121a30; --panel2: #17213c; --text: #e6ecff; --muted: #96a2c3;
  --critical: #f43f5e; --high: #fb7185; --medium: #f59e0b; --low: #38bdf8; --info: #94a3b8;
  --ok: #34d399; --border: #24304f; --accent: #818cf8;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  line-height: 1.55; }
a { color: var(--accent); }
header.cover { padding: 56px 6vw 40px; background: radial-gradient(1200px 400px at 20% -10%, #1e2a56, transparent), var(--bg);
  border-bottom: 1px solid var(--border); }
header.cover h1 { font-size: 2.4rem; margin: 0 0 8px; letter-spacing: -0.02em; }
header.cover .meta { color: var(--muted); font-size: 0.95rem; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 0.72rem;
  font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #08101f; }
.badge.critical { background: var(--critical); color: #fff; }
.badge.high { background: var(--high); color: #2b0710; }
.badge.medium { background: var(--medium); }
.badge.low { background: var(--low); color: #06121c; }
.badge.info { background: var(--info); }
main { padding: 32px 6vw 80px; max-width: 1200px; margin: 0 auto; }
section { margin-bottom: 48px; }
h2 { font-size: 1.5rem; margin: 0 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
h3 { font-size: 1.1rem; margin: 24px 0 8px; }
.grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 18px; }
.card .value { font-size: 1.9rem; font-weight: 700; }
.card .label { color: var(--muted); font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.06em; }
.metric-critical { border-left: 4px solid var(--critical); }
.metric-high { border-left: 4px solid var(--high); }
.metric-medium { border-left: 4px solid var(--medium); }
.metric-low { border-left: 4px solid var(--low); }
.bars { display: flex; flex-direction: column; gap: 10px; margin-top: 8px; }
.bar-row { display: grid; grid-template-columns: 100px 1fr 40px; align-items: center; gap: 12px; }
.bar { height: 10px; border-radius: 999px; background: var(--panel2); overflow: hidden; }
.bar > span { display: block; height: 100%; }
.bar-critical > span { background: var(--critical); }
.bar-high > span { background: var(--high); }
.bar-medium > span { background: var(--medium); }
.bar-low > span { background: var(--low); }
.bar-info > span { background: var(--info); }
.toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 12px 0 20px; }
.toolbar input[type=search] { flex: 1 1 240px; background: var(--panel); color: var(--text);
  border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; font-size: 0.95rem; }
.chip { background: var(--panel); border: 1px solid var(--border); color: var(--muted);
  border-radius: 999px; padding: 6px 12px; font-size: 0.8rem; cursor: pointer; }
.chip.active { border-color: var(--accent); color: var(--text); background: #1b2450; }
.finding { background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
  margin-bottom: 16px; overflow: hidden; }
.finding summary { cursor: pointer; padding: 16px 18px; display: flex; gap: 12px; align-items: center;
  list-style: none; }
.finding summary::-webkit-details-marker { display: none; }
.finding .title { font-weight: 600; flex: 1; }
.finding .where { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.8rem; word-break: break-all; }
.finding .body { padding: 0 18px 18px; border-top: 1px solid var(--border); }
.kv { display: grid; grid-template-columns: 160px 1fr; gap: 4px 12px; font-size: 0.9rem; margin: 12px 0; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; word-break: break-word; }
pre { background: #070c18; border: 1px solid var(--border); border-radius: 10px; padding: 12px;
  overflow: auto; font-size: 0.8rem; max-height: 420px; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
ol.steps li, ul.plain li { margin-bottom: 6px; }
.chain { border-left: 3px solid var(--accent); padding: 8px 0 8px 16px; margin-bottom: 18px; }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
.muted { color: var(--muted); }
.warning { background: #2a1d0b; border: 1px solid #7c4a03; color: #fbbf24; padding: 12px; border-radius: 10px; }
footer { padding: 24px 6vw 60px; color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border); }
@media print {
  body { background: #fff; color: #000; }
  .card, .finding, pre { border-color: #ccc; }
  .chip, .toolbar input { display: none; }
  details { open: true; }
}
"""

_JS = """
(function () {
  const findings = Array.from(document.querySelectorAll('[data-finding]'));
  const chips = Array.from(document.querySelectorAll('.chip[data-sev]'));
  const search = document.getElementById('search');
  let active = 'all';
  function apply() {
    const term = (search && search.value || '').toLowerCase();
    findings.forEach(function (el) {
      const sev = el.getAttribute('data-sev');
      const text = el.textContent.toLowerCase();
      const sevOk = active === 'all' || sev === active;
      const textOk = !term || text.indexOf(term) !== -1;
      el.style.display = (sevOk && textOk) ? '' : 'none';
    });
    const count = document.getElementById('visible-count');
    if (count) {
      const shown = findings.filter(function (el) { return el.style.display !== 'none'; }).length;
      count.textContent = shown + ' of ' + findings.length + ' findings shown';
    }
  }
  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      chips.forEach(function (other) { other.classList.remove('active'); });
      chip.classList.add('active');
      active = chip.getAttribute('data-sev');
      apply();
    });
  });
  if (search) { search.addEventListener('input', apply); }
  document.querySelectorAll('[data-expand]').forEach(function (button) {
    button.addEventListener('click', function () {
      const target = button.getAttribute('data-expand');
      const nodes = document.querySelectorAll('[data-finding]');
      const expand = button.textContent.indexOf('Expand') === 0;
      nodes.forEach(function (node) { node.open = expand; });
      button.textContent = expand ? 'Collapse all' : 'Expand all';
    });
  });
  apply();
})();
"""


def render_html(model: ReportModel, *, include_evidence: bool = True, logo: str = "") -> str:
    view = build_executive_view(model)
    counts = model.counts
    total = max(1, counts.get("total", 0))
    parts: list[str] = []
    add = parts.append
    add("<!doctype html>")
    add('<html lang="en"><head><meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add(f"<title>{_e(model.title)} — {_e(model.scan_id)}</title>")
    add(f"<style>{_CSS}</style>")
    add("</head><body>")
    add('<header class="cover">')
    if logo:
        add(f'<img src="{_e(logo)}" alt="logo" style="height:42px;margin-bottom:18px">')
    add(f"<h1>{_e(model.title)}</h1>")
    client = (model.engagement or {}).get("client", "")
    if client:
        add(f'<p class="meta">{_e(client)}</p>')
    add('<p class="meta">')
    add(f"Scan <code>{_e(model.scan_id)}</code> · {humanize_duration(model.duration)} · profile {_e(model.profile)} · generated {_e(model.generated_at)}")
    add("</p>")
    add('<p class="meta">')
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = counts.get(severity.value, 0)
        if count:
            add(f'<span class="badge {severity.value}">{count} {severity.value}</span> ')
    add(f'<span class="badge info">{counts.get("info", 0)} info</span>')
    add("</p>")
    add("</header>")
    add("<main>")

    # Executive summary -------------------------------------------------
    add("<section id='summary'>")
    add("<h2>Executive summary</h2>")
    add(f"<p><strong>{_e(view.headline)}</strong></p>")
    for paragraph in view.narrative:
        add(f"<p>{_e(paragraph)}</p>")
    add('<div class="grid">')
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        add(
            f'<div class="card metric-{severity.value}"><div class="label">{severity.value}</div>'
            f'<div class="value">{counts.get(severity.value, 0)}</div></div>'
        )
    add(
        f'<div class="card"><div class="label">Verified</div><div class="value">{len(model.verified_findings)}</div></div>'
    )
    add(
        f'<div class="card"><div class="label">Exploited</div><div class="value">{len(model.exploited_findings)}</div></div>'
    )
    add(f'<div class="card"><div class="label">Risk score</div><div class="value">{model.risk_score:.1f}</div></div>')
    add("</div>")
    add('<div class="bars">')
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = counts.get(severity.value, 0)
        width = 100.0 * count / total
        add('<div class="bar-row">')
        add(f'<span class="muted">{severity.value.title()}</span>')
        add(f'<div class="bar bar-{severity.value}"><span style="width:{width:.1f}%"></span></div>')
        add(f"<span>{count}</span>")
        add("</div>")
    add("</div>")
    add("</section>")

    # Scope -------------------------------------------------------------
    add("<section id='scope'>")
    add("<h2>Scope and engagement</h2>")
    add('<table><thead><tr><th>Target</th><th>Authentication context</th></tr></thead><tbody>')
    for target in model.targets:
        add(f"<tr><td><code>{_e(target.get('url', ''))}</code></td><td>{_e(target.get('auth_context', 'anonymous'))}</td></tr>")
    add("</tbody></table>")
    engagement = model.engagement or {}
    if engagement:
        add('<dl class="kv">')
        for key in ("engagement", "client", "operator", "authorized_by", "expires_at"):
            if engagement.get(key):
                add(f"<dt>{_e(key.replace('_', ' ').title())}</dt><dd>{_e(str(engagement[key]))}</dd>")
        add("</dl>")
    if model.warnings:
        add('<div class="warning"><strong>Limitations</strong><ul class="plain">')
        for warning in model.warnings:
            add(f"<li>{_e(warning)}</li>")
        add("</ul></div>")
    add("</section>")

    # Attack chains -----------------------------------------------------
    if model.chains:
        add("<section id='chains'>")
        add("<h2>Attack paths</h2>")
        for chain in model.chains:
            add('<div class="chain">')
            add(f"<h3>{_e(chain.get('name', 'Attack path'))} — <span class='badge {_e(chain.get('severity', 'medium'))}'>{_e(chain.get('severity', ''))}</span></h3>")
            add(f"<p>{_e(chain.get('impact', ''))}</p>")
            add('<ol class="steps">')
            for step in chain.get("steps", []):
                add(f"<li><strong>{_e(step.get('title', ''))}</strong> — {_e(step.get('why', ''))}</li>")
            add("</ol></div>")
        add("</section>")

    # Findings ----------------------------------------------------------
    add("<section id='findings'>")
    add("<h2>Findings</h2>")
    add('<div class="toolbar">')
    add('<button class="chip active" data-sev="all">All</button>')
    for severity in ("critical", "high", "medium", "low", "info"):
        add(f'<button class="chip" data-sev="{severity}">{severity.title()}</button>')
    add('<input id="search" type="search" placeholder="Search findings, endpoints, parameters...">')
    add('<button class="chip" data-expand="all">Expand all</button>')
    add("</div>")
    add(f'<p class="muted" id="visible-count">{len(model.findings)} of {len(model.findings)} findings shown</p>')
    for finding in model.findings:
        add(
            f'<details class="finding" data-finding data-sev="{finding.severity.value}">'
        )
        add("<summary>")
        add(f'<span class="badge {finding.severity.value}">{finding.severity.value}</span>')
        add(f'<span class="title">{_e(finding.title)}</span>')
        add(f'<span class="where">{_e(finding.method)} {_e(_short_url(finding.url))}</span>')
        add("</summary>")
        add('<div class="body">')
        add('<dl class="kv">')
        add(f"<dt>Finding ID</dt><dd><code>{_e(finding.id)}</code></dd>")
        add(f"<dt>Severity</dt><dd>{_e(finding.severity.value)} ({finding.effective_score:.1f})</dd>")
        if finding.vector:
            add(f"<dt>CVSS</dt><dd><code>{_e(finding.vector)}</code></dd>")
        add(f"<dt>Confidence</dt><dd>{_e(finding.confidence.value)}</dd>")
        add(f"<dt>Verified / exploited</dt><dd>{'yes' if finding.verified else 'no'} / {'yes' if finding.exploited else 'no'}</dd>")
        add(f"<dt>Endpoint</dt><dd><code>{_e(finding.method)} {_e(finding.url)}</code></dd>")
        if finding.parameter:
            add(f"<dt>Parameter</dt><dd><code>{_e(finding.parameter)}</code> ({_e(finding.location)})</dd>")
        if finding.cwe:
            add(f"<dt>CWE</dt><dd>{_e(', '.join(finding.cwe))}</dd>")
        add("</dl>")
        add(f"<p>{_e(finding.description)}</p>")
        if finding.impact:
            add(f"<p><strong>Impact.</strong> {_e(finding.impact)}</p>")
        if finding.payload:
            add("<h3>Proof payload</h3>")
            add(f"<pre><code>{_e(finding.payload[:4000])}</code></pre>")
        if finding.metadata.get("proof_output"):
            add("<h3>Exploitation output</h3>")
            add(f"<pre><code>{_e(str(finding.metadata['proof_output'])[:4000])}</code></pre>")
        if include_evidence and finding.evidence:
            add("<h3>Evidence</h3>")
            for evidence in finding.evidence[:3]:
                add(f"<p class='muted'>{_e(evidence.kind)} · {_e(evidence.summary)}</p>")
                if evidence.exchange:
                    add(f"<pre><code>{_e(evidence.exchange.request_text()[:4000])}</code></pre>")
                    add(f"<pre><code>{_e(evidence.exchange.response_text()[:4000])}</code></pre>")
        if finding.remediation.summary or finding.remediation.steps:
            add("<h3>Remediation</h3>")
            add(f"<p>{_e(finding.remediation.summary)}</p>")
            add('<ol class="steps">')
            for step in finding.remediation.steps:
                add(f"<li>{_e(step)}</li>")
            add("</ol>")
            if finding.remediation.verification:
                add(f"<p><strong>Verification.</strong> {_e(finding.remediation.verification)}</p>")
            if finding.remediation.references:
                add("<p class='muted'>References: " + " · ".join(_e(reference) for reference in finding.remediation.references) + "</p>")
        add("</div></details>")
    add("</section>")

    # Remediation plan --------------------------------------------------
    add("<section id='plan'>")
    add("<h2>Remediation plan</h2>")
    plan = model.remediation_plan()
    if plan:
        add("<table><thead><tr><th>Priority</th><th>Action</th><th>Effort</th><th>SLA</th><th>Owner</th><th>Findings</th></tr></thead><tbody>")
        for item in plan[:20]:
            add(
                "<tr>"
                f"<td><span class='badge {_e(item['severity'])}'>{_e(item['severity'])}</span></td>"
                f"<td>{_e(item['summary'])}</td>"
                f"<td>{_e(item['effort'])}</td>"
                f"<td>{item['sla_days']} days</td>"
                f"<td>{_e(item.get('owner_hint') or 'Engineering')}</td>"
                f"<td>{_e(', '.join(f['id'] for f in item['findings']))}</td>"
                "</tr>"
            )
        add("</tbody></table>")
    else:
        add("<p>No remediation actions required.</p>")
    add("</section>")

    # Methodology -------------------------------------------------------
    add("<section id='method'>")
    add("<h2>Methodology</h2>")
    add('<ul class="plain">')
    for item in model.methodology:
        add(f"<li>{_e(item)}</li>")
    add("</ul>")
    add("<h3>Technology fingerprint</h3>")
    technologies = (model.technologies or {}).get("technologies", [])
    if technologies:
        add("<table><thead><tr><th>Component</th><th>Category</th><th>Version</th><th>Confidence</th></tr></thead><tbody>")
        for technology in technologies:
            add(
                f"<tr><td>{_e(technology.get('name', ''))}</td><td>{_e(technology.get('category', ''))}</td>"
                f"<td>{_e(technology.get('version') or '-')}</td><td>{_e(technology.get('confidence', ''))}</td></tr>"
            )
        add("</tbody></table>")
    else:
        add("<p class='muted'>No technology fingerprint recorded.</p>")
    if model.waf and model.waf.get("detected"):
        add(f"<p><strong>WAF:</strong> {_e(model.waf.get('vendor', 'unknown'))} (confidence {_e(model.waf.get('confidence', ''))})</p>")
    add("<h3>Scan statistics</h3>")
    add('<dl class="kv">')
    for key, value in (model.stats or {}).items():
        add(f"<dt>{_e(key.replace('_', ' ').title())}</dt><dd>{_e(str(value))}</dd>")
    add(f"<dt>Evidence records</dt><dd>{model.evidence_count}</dd>")
    add(f"<dt>Report digest</dt><dd><code>{_e(model.digest)}</code></dd>")
    add("</dl>")
    add("</section>")

    add("</main>")
    add("<footer>")
    add(
        f"Generated by Candix {_e(model.version)} · {_e(model.generated_at)} · "
        "Evidence files are hash-chained and redacted. This document contains confidential security information."
    )
    add("</footer>")
    add(f"<script>{_JS}</script>")
    add("</body></html>")
    return "\n".join(parts)


def _e(value: Any) -> str:
    return html_module.escape(str(value), quote=True)


def _short_url(url: str, limit: int = 90) -> str:
    return url if len(url) <= limit else url[: limit - 1] + "…"


def render_finding_fragment(finding: Any) -> str:
    """Small helper used by integrations that need an HTML snippet."""

    return (
        f"<article><h3>{_e(finding.title)}</h3>"
        f"<p><strong>{_e(finding.severity.value)}</strong> · {_e(finding.url)}</p>"
        f"<p>{_e(finding.description)}</p></article>"
    )


def to_json_script(payload: dict[str, Any]) -> str:
    """Embed data in HTML without allowing a closing script tag injection."""

    text = json.dumps(payload, ensure_ascii=True)
    return text.replace("</", "<\\/")
