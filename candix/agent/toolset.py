"""Concrete tools: HTTP, detection, catalogue lookups, facts and proof.

Every tool is a thin adapter over machinery Candix already has (the HTTP client,
the detector catalogue, the payload catalogue, the evidence store). The adapter
adds exactly three things: a JSON schema the model can be held to, a compact
structured result, and the bookkeeping the run needs (asset graph, findings).
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlsplit

from candix.agent.exploits import tool_exploit_run
from candix.agent.fuzz_tools import tool_fuzz_run
from candix.agent.api_spec import tool_api_spec
from candix.agent.auth_tools import tool_auth_flow, tool_jwt_inspect, tool_oauth_flow
from candix.agent.facts import Confidence, Fact, FactSource
from candix.agent.graphql import tool_graphql
from candix.agent.graph import EdgeKind, endpoint_key
from candix.agent.tools import Tool, ToolContext, ToolError, ToolRegistry, ToolResult
from candix.agent.web_probe import tool_web_probe
from candix.agent.ws_probe import tool_ws_probe
from candix.core.finding import Finding
from candix.core.severity import Severity

# ----------------------------------------------------------------------
# schemas

_URL = {"type": "string", "description": "absolute http(s) URL inside the engagement scope", "minLength": 8}
_METHOD = {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS"], "default": "GET"}
_HEADERS = {"type": "object", "description": "extra request headers", "additionalProperties": {"type": "string"}}

HTTP_SCHEMA = {
    "type": "object",
    "properties": {
        "url": _URL,
        "method": _METHOD,
        "headers": _HEADERS,
        "body": {"type": "string", "description": "raw request body"},
        "json_body": {"type": "object", "description": "JSON body, mutually exclusive with body"},
        "follow": {"type": "boolean", "default": True},
        "max_bytes": {"type": "integer", "default": 20000, "minimum": 200, "maximum": 200000},
        "save_body": {"type": "boolean", "default": False, "description": "store the full body as an artefact"},
        "note": {"type": "string", "description": "why this request matters"},
    },
    "required": ["url"],
}

BATCH_SCHEMA = {
    "type": "object",
    "properties": {
        "urls": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 40},
        "method": _METHOD,
        "headers": _HEADERS,
        "stop_on_match": {"type": "string", "description": "regex; stop early when a body matches"},
    },
    "required": ["urls"],
}

DETECT_SCHEMA = {
    "type": "object",
    "properties": {
        "detectors": {"type": "array", "items": {"type": "string"}, "description": "detector ids; empty means all applicable"},
        "categories": {"type": "array", "items": {"type": "string"}},
        "include_intrusive": {"type": "boolean", "default": True},
        "max_findings": {"type": "integer", "default": 25, "minimum": 1, "maximum": 200},
    },
}

FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "min_severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"], "default": "info"},
        "category": {"type": "string"},
        "verified_only": {"type": "boolean", "default": False},
        "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200},
    },
}

PAYLOAD_SCHEMA = {
    "type": "object",
    "properties": {
        "family": {"type": "string", "description": "payload family, e.g. xss, sqli, ssti"},
        "limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 200},
    },
    "required": ["family"],
}

FACT_SCHEMA = {
    "type": "object",
    "properties": {
        "claim": {"type": "string", "minLength": 3, "maxLength": 400},
        "source": {
            "type": "string",
            "enum": ["target_response", "tool_output", "third_party_intel", "operator_input", "inference"],
        },
        "confidence": {"type": "string", "enum": ["observed", "corroborated", "inferred"]},
        "subject": {"type": "string", "description": "asset node id or host this fact is about"},
        "evidence": {"type": "array", "items": {"type": "string"}, "description": "observation digests or artefact paths"},
    },
    "required": ["claim", "source", "confidence"],
}

PROVE_SCHEMA = {
    "type": "object",
    "properties": {
        "claim": {"type": "string"},
        "fact_ids": {"type": "array", "items": {"type": "string"}},
        "note": {"type": "string"},
    },
    "required": ["claim"],
}

NOTE_SCHEMA = {
    "type": "object",
    "properties": {
        "text": {"type": "string", "minLength": 2},
        "kind": {"type": "string", "enum": ["note", "hypothesis", "question", "todo"], "default": "note"},
    },
    "required": ["text"],
}

FINGERPRINT_SCHEMA = {
    "type": "object",
    "properties": {"url": _URL},
    "required": ["url"],
}

CRAWL_SCHEMA = {
    "type": "object",
    "properties": {
        "url": _URL,
        "depth": {"type": "integer", "default": 1, "minimum": 1, "maximum": 3},
        "max_pages": {"type": "integer", "default": 12, "minimum": 1, "maximum": 60},
    },
    "required": ["url"],
}

FINISH_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "what the run established"},
        "remaining": {"type": "array", "items": {"type": "string"}, "description": "work that is still open"},
    },
    "required": ["summary"],
}


# ----------------------------------------------------------------------
# helpers


def _context(ctx: ToolContext) -> Any:
    return ctx.state.get("scan_context")


def _session(ctx: ToolContext) -> Any:
    context = _context(ctx)
    if context is None or not hasattr(context, "http"):
        raise ToolError("no HTTP client in this run; start the agent with a scan context")
    return context.http


def _trim(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n… [{len(text) - limit} more bytes]", True


def _header_subset(response: Any) -> dict[str, str]:
    interesting = (
        "content-type",
        "content-length",
        "server",
        "location",
        "set-cookie",
        "x-powered-by",
        "allow",
        "access-control-allow-origin",
        "www-authenticate",
        "x-frame-options",
        "content-security-policy",
    )
    result: dict[str, str] = {}
    headers = getattr(response, "headers", None)
    if headers is None:
        return result
    for name in interesting:
        value = headers.get(name)
        if value:
            result[name] = str(value)[:200]
    return result


# ----------------------------------------------------------------------
# tools


def http_request(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    url = str(arguments["url"])
    method = str(arguments.get("method", "GET")).upper()
    max_bytes = int(arguments.get("max_bytes", 20000))
    decision = ctx.guard.enforce(url, method=method)
    client = _session(ctx)
    started = time.monotonic()
    kwargs: dict[str, Any] = {
        "headers": dict(arguments.get("headers") or {}),
        "allow_redirects": bool(arguments.get("follow", True)),
        "tag": "agent",
    }
    if arguments.get("json_body") is not None:
        kwargs["json_body"] = arguments["json_body"]
    elif arguments.get("body"):
        kwargs["data"] = str(arguments["body"])
    response = client.request(method, url, **kwargs)
    elapsed = time.monotonic() - started
    body = getattr(response, "text", "") or ""
    trimmed, was_trimmed = _trim(body, max_bytes)
    headers = _header_subset(response)

    context = _context(ctx)
    if context is not None:
        try:
            context.add_endpoint(_endpoint(url, method, getattr(response, "status", 0), headers))
        except Exception:
            pass

    assets = ctx.state.get("assets")
    if assets is not None:
        assets.add_endpoint(method, url, status=int(getattr(response, "status", 0) or 0))
    ctx.telemetry.increment("http.requests")

    saved = ""
    if arguments.get("save_body") and ctx.artifacts is not None:
        name = f"body-{abs(hash(url)) % 10**8}-{int(time.time())}.txt"
        saved = ctx.save_artifact(name, body)

    result = {
        "status": int(getattr(response, "status", 0) or 0),
        "url": getattr(response, "url", url),
        "elapsed_ms": round(elapsed * 1000, 1),
        "length": len(body),
        "headers": headers,
        "body": trimmed,
        "truncated": was_trimmed,
        "redirected": bool(getattr(response, "redirected", False)),
        "note": arguments.get("note", ""),
        "artefact": saved,
    }
    result["summary"] = f"{method} {url} -> {result['status']} ({len(body)} bytes, {result['elapsed_ms']} ms)"
    return result


def _endpoint(url: str, method: str, status: int, headers: dict[str, str]) -> Any:
    from candix.core.context import Endpoint

    return Endpoint(url=url, method=method, response_hint={"status": status, "headers": headers}, source="agent")


def http_batch(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    import re

    urls = [str(item) for item in arguments.get("urls") or []]
    method = str(arguments.get("method", "GET")).upper()
    headers = dict(arguments.get("headers") or {})
    pattern = str(arguments.get("stop_on_match") or "")
    compiled = re.compile(pattern) if pattern else None
    client = _session(ctx)
    rows: list[dict[str, Any]] = []
    matched = ""
    for url in urls:
        if ctx.budget.remaining_seconds <= 0:
            break
        decision = ctx.guard.check_url(url, method=method)
        if not decision.allowed:
            rows.append({"url": url, "blocked": decision.reason})
            continue
        ctx.guard.record(url, method=method)
        try:
            response = client.request(method, url, headers=headers, tag="agent-batch")
        except Exception as error:
            rows.append({"url": url, "error": str(error)[:120]})
            continue
        body = getattr(response, "text", "") or ""
        status = int(getattr(response, "status", 0) or 0)
        rows.append({"url": url, "status": status, "length": len(body)})
        if compiled is not None and compiled.search(body):
            matched = url
            rows[-1]["matched"] = True
            break
        ctx.budget.spend_tool_call()
    summary = f"{len(rows)} response(s); statuses {sorted({row.get('status') for row in rows if row.get('status')})}"
    return {"summary": summary, "rows": rows, "matched": matched}


def detect_run(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    from candix.detectors.base import select_detectors

    context = _context(ctx)
    if context is None:
        raise ToolError("detection needs a scan context")
    only = [str(item) for item in arguments.get("detectors") or []]
    categories = [str(item) for item in arguments.get("categories") or []]
    classes = select_detectors(
        context,
        only=only,
        categories=categories,
        include_intrusive=bool(arguments.get("include_intrusive", True)),
    )
    limit = int(arguments.get("max_findings", 25))
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for detector_class in classes:
        if ctx.budget.exhausted():
            break
        detector = detector_class(context)
        try:
            for finding in detector.run() or ():
                if finding is None:
                    continue
                findings.append(_finding_row(finding))
                if len(findings) >= limit:
                    break
        except Exception as error:  # a broken detector must not kill the run
            errors.append(f"{detector_class.meta.id}: {error}")
        if len(findings) >= limit:
            break
    assets = ctx.state.get("assets")
    if assets is not None:
        for row in findings:
            assets.add_finding(row)
    ctx.telemetry.increment("detect.findings", len(findings))
    summary = f"{len(findings)} finding(s) from {len(classes)} detector(s)"
    return {"summary": summary, "findings": findings, "errors": errors, "detectors": [cls.meta.id for cls in classes]}


def _finding_row(finding: Finding) -> dict[str, Any]:
    return {
        "id": getattr(finding, "id", ""),
        "title": getattr(finding, "title", ""),
        "severity": getattr(getattr(finding, "severity", None), "value", "info"),
        "url": getattr(finding, "url", ""),
        "method": getattr(finding, "method", "GET"),
        "parameter": getattr(finding, "parameter", ""),
        "category": getattr(finding, "category", ""),
        "verified": bool(getattr(finding, "verified", False)),
        "score": round(float(getattr(finding, "effective_score", 0.0) or 0.0), 1),
    }


def findings_list(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    context = _context(ctx)
    if context is None:
        raise ToolError("findings need a scan context")
    threshold = Severity.parse(str(arguments.get("min_severity", "info")))
    category = str(arguments.get("category") or "")
    verified_only = bool(arguments.get("verified_only", False))
    limit = int(arguments.get("limit", 50))
    try:
        stored = list(context.findings)
    except Exception:  # pragma: no cover - context without findings
        stored = []
    rows = []
    for finding in stored:
        if finding.severity.rank < threshold.rank:
            continue
        if category and finding.category != category:
            continue
        if verified_only and not finding.verified:
            continue
        rows.append(_finding_row(finding))
    rows = rows[:limit]
    return {"summary": f"{len(rows)} finding(s) at or above {threshold.value}", "findings": rows}


def payloads_search(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    from candix.catalog import payloads

    family = str(arguments["family"]).strip().lower()
    limit = int(arguments.get("limit", 20))
    try:
        values = payloads.get_payloads(family)
    except Exception:
        values = []
    if not values:
        matched = [name for name in payloads.families() if family in name]
        for name in matched:
            values.extend(payloads.get_payloads(name))
    values = values[:limit]
    return {
        "summary": f"{len(values)} payload(s) for {family}",
        "family": family,
        "payloads": values,
        "families": payloads.families()[:20],
    }


def fingerprint(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    from candix.recon.tech import fingerprint_response

    url = str(arguments["url"])
    ctx.guard.enforce(url, method="GET")
    response = _session(ctx).get(url, tag="agent-fingerprint")
    result = fingerprint_response(response)
    assets = ctx.state.get("assets")
    rows = []
    for technology in getattr(result, "technologies", []) or []:
        row = {
            "name": getattr(technology, "name", ""),
            "category": getattr(technology, "category", ""),
            "version": getattr(technology, "version", ""),
            "confidence": getattr(technology, "confidence", 0.0),
        }
        rows.append(row)
        if assets is not None:
            assets.add_technology(row["name"], version=row["version"], category=row["category"], confidence=float(row["confidence"]))
    return {"summary": f"{len(rows)} technology signal(s) on {url}", "technologies": rows}


def crawl(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    from candix.recon.crawler import Crawler

    context = _context(ctx)
    if context is None:
        raise ToolError("crawling needs a scan context")
    start = str(arguments["url"])
    ctx.guard.enforce(start, method="GET")
    max_pages = int(arguments.get("max_pages", 12))
    depth = int(arguments.get("depth", 1))
    crawler = Crawler(context, max_pages=max_pages, max_depth=depth)
    result = crawler.crawl([start])
    assets = ctx.state.get("assets")
    rows: list[dict[str, Any]] = []
    for url in getattr(result, "visited", []) or []:
        rows.append({"url": str(url), "method": "GET"})
        if assets is not None:
            assets.add_endpoint("GET", str(url))
    for endpoint in list(getattr(context, "endpoints", []) or []):
        url = str(getattr(endpoint, "url", ""))
        method = str(getattr(endpoint, "method", "GET"))
        if not url:
            continue
        if assets is not None:
            assets.add_endpoint(method, url)
        if getattr(endpoint, "params", None):
            for parameter in endpoint.params:
                name = getattr(parameter, "name", "")
                if name and assets is not None:
                    node = assets.add_endpoint(method, url)
                    assets.add_parameter(node.id, str(name), location=str(getattr(parameter, "location", "query")))
    summary = getattr(result, "summary", lambda: {})()
    return {
        "summary": f"crawled {len(rows)} page(s), {summary.get('endpoints_added', 0)} endpoint(s) added from {start}",
        "pages": rows[:60],
        "stats": summary,
    }


def _accepts(function: Any, parameter: str) -> bool:
    import inspect

    try:
        return parameter in inspect.signature(function).parameters
    except (TypeError, ValueError):
        return False


def facts_add(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    store = ctx.state.get("facts")
    if store is None:
        raise ToolError("no fact store in this run")
    source = FactSource(str(arguments["source"]))
    confidence = Confidence(str(arguments["confidence"]))
    if source is FactSource.TARGET_RESPONSE and confidence is Confidence.OBSERVED:
        # A fact read straight off the target is never independent evidence.
        pass
    fact = Fact(
        claim=str(arguments["claim"]),
        source=source,
        confidence=confidence,
        subject=str(arguments.get("subject", "")),
        evidence=[str(item) for item in arguments.get("evidence") or []],
        created_by="worker",
    )
    stored, action = store.add(fact)
    ctx.telemetry.increment(f"facts.{action}")
    return {
        "summary": f"fact {action}: {stored.claim[:100]}",
        "action": action,
        "fact": stored.to_dict(),
        "provable": stored.provable,
    }


def prove_goal(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    store = ctx.state.get("facts")
    if store is None:
        raise ToolError("no fact store in this run")
    claim = str(arguments["claim"])
    requested = [str(item) for item in arguments.get("fact_ids") or []]
    candidates = [store.get(item) for item in requested] if requested else store.find(claim)
    candidates = [fact for fact in candidates if fact is not None]
    if not candidates:
        # The claim is usually the goal sentence, which no single fact repeats.
        # Fall back to everything the run observed directly.
        candidates = list(store.provable())
    usable = [fact for fact in candidates if fact.provable]
    rejected = [
        {"id": fact.id, "reason": _rejection(fact)} for fact in candidates if not fact.provable
    ]
    if not usable:
        ctx.telemetry.increment("proofs.rejected")
        reasons = ", ".join(item["reason"] for item in rejected) or "no matching facts"
        return {
            "summary": f"goal not proven: {reasons}",
            "proven": False,
            "rejected": rejected,
        }
    proofs = ctx.state.setdefault("proofs", [])
    proofs.append({"claim": claim, "facts": [fact.to_dict() for fact in usable], "note": str(arguments.get("note", ""))})
    ctx.telemetry.increment("proofs.accepted")
    return {
        "summary": f"goal proven with {len(usable)} independent fact(s)",
        "proven": True,
        "facts": [fact.to_dict() for fact in usable],
        "rejected": rejected,
    }


def _rejection(fact: Fact) -> str:
    if fact.source is FactSource.TARGET_RESPONSE:
        return "fact came from the target; the target cannot prove itself"
    if fact.confidence is not Confidence.OBSERVED:
        return f"confidence {fact.confidence.value} is not observed"
    return "fact is not provable"


def notes_write(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    blackboard = ctx.state.get("blackboard")
    if blackboard is None:
        raise ToolError("no blackboard in this run")
    text = str(arguments["text"])
    kind = str(arguments.get("kind", "note"))
    if kind == "hypothesis":
        blackboard.hypothesise(text)
    elif kind == "question":
        blackboard.question(text)
    elif kind == "todo":
        blackboard.todo(text)
    else:
        blackboard.note(text, kind=kind, author="worker")
    return {"summary": f"{kind} recorded", "kind": kind, "text": text}


def evidence_capture(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    observation = ctx.state.get("last_observation") or {}
    if not observation:
        raise ToolError("nothing to capture")
    if ctx.artifacts is None:
        raise ToolError("this run has no artefact directory")
    payload = json.dumps(observation, indent=2, sort_keys=True, ensure_ascii=False)
    path = ctx.save_artifact(f"evidence-{int(time.time())}.json", payload)
    return {"summary": f"evidence written to {path}", "path": path}


def replay_request(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    history = ctx.state.get("history") or []
    if not history:
        raise ToolError("no requests to replay")
    try:
        index = int(arguments.get("index", -1))
    except (TypeError, ValueError):
        index = -1
    entry = history[index]
    url = str(entry.get("url", ""))
    method = str(entry.get("method", "GET"))
    ctx.guard.enforce(url, method=method)
    response = _session(ctx).request(method, url, headers=dict(entry.get("headers") or {}), tag="agent-replay")
    body = getattr(response, "text", "") or ""
    return {
        "summary": f"replayed {method} {url} -> {getattr(response, 'status', 0)}",
        "status": int(getattr(response, "status", 0) or 0),
        "body": body[:4000],
    }


def finish(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    summary = str(arguments["summary"])
    remaining = [str(item) for item in arguments.get("remaining") or []]
    ctx.state.setdefault("finish", {})["summary"] = summary
    ctx.state["finish"]["remaining"] = remaining
    blackboard = ctx.state.get("blackboard")
    if blackboard is not None:
        for item in remaining:
            blackboard.question(item)
    return {"summary": summary, "remaining": remaining, "finished": True}


def endpoints_list(ctx: ToolContext, arguments: dict[str, Any]) -> dict[str, Any]:
    assets = ctx.state.get("assets")
    if assets is None:
        raise ToolError("no asset graph in this run")
    limit = int(arguments.get("limit", 50))
    rows = [
        {
            "url": node.attributes.get("url", ""),
            "method": node.attributes.get("method", "GET"),
            "status": node.attributes.get("status", 0),
            "path": node.attributes.get("path", "/"),
        }
        for node in assets.endpoints()[:limit]
    ]
    return {"summary": f"{len(rows)} known endpoint(s)", "endpoints": rows, "coverage": assets.coverage()}


ENDPOINTS_SCHEMA = {
    "type": "object",
    "properties": {"limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200}},
}

REPLAY_SCHEMA = {
    "type": "object",
    "properties": {"index": {"type": "integer", "default": -1}},
}


PROBE_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "base URL to probe"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 80},
        "extensions": {"type": "boolean", "default": True},
    },
    "required": ["url"],
    "additionalProperties": False,
}

SPEC_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "origin or base path that serves the spec"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 12, "default": 12},
    },
    "required": ["url"],
    "additionalProperties": False,
}

GRAPHQL_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "GraphQL endpoint or origin"},
        "query": {"type": "string", "description": "GraphQL document; empty means introspect"},
        "variables": {"type": "object"},
        "headers": {"type": "object"},
    },
    "required": ["url"],
    "additionalProperties": False,
}


AUTH_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "login page or origin"},
        "username": {"type": "string"},
        "password": {"type": "string"},
    },
    "required": ["url"],
    "additionalProperties": False,
}

JWT_SCHEMA = {
    "type": "object",
    "properties": {
        "token": {"type": "string"},
        "url": {"type": "string", "description": "endpoint that should reject an unsigned token"},
        "header": {"type": "string", "default": "Authorization"},
        "crack": {"type": "boolean", "default": True},
    },
    "additionalProperties": False,
}

OAUTH_SCHEMA = {
    "type": "object",
    "properties": {
        "issuer": {"type": "string"},
        "client_id": {"type": "string"},
        "redirect_uri": {"type": "string"},
        "scope": {"type": "string"},
    },
    "additionalProperties": False,
}

WS_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string"},
        "timeout": {"type": "number", "minimum": 1, "maximum": 15, "default": 4},
    },
    "required": ["url"],
    "additionalProperties": False,
}


FUZZ_SCHEMA = {
    "type": "object",
    "properties": {
        "iterations": {"type": "integer", "minimum": 10, "maximum": 400, "default": 80},
        "strategy": {"type": "string", "enum": ["balanced", "breadth", "depth", "random"], "default": "balanced"},
        "params": {"type": "array", "items": {"type": "string"}},
        "targets": {"type": "array", "items": {"type": "string"}},
        "stop_on_finding": {"type": "boolean", "default": False},
    },
    "additionalProperties": False,
}


def default_registry() -> ToolRegistry:
    """The tool set every agent run starts with."""

    return ToolRegistry(
        [
            Tool(
                "http.request",
                "Send one HTTP request to an in-scope URL and return status, headers and a bounded body.",
                http_request,
                HTTP_SCHEMA,
                max_calls=60,
                tags=("http", "active"),
            ),
            Tool(
                "http.batch",
                "Send the same method to up to 40 URLs, returning status and length per URL.",
                http_batch,
                BATCH_SCHEMA,
                max_calls=10,
                timeout=180.0,
                tags=("http", "enumeration"),
            ),
            Tool(
                "detect.run",
                "Run Candix detectors against the current context and return their findings.",
                detect_run,
                DETECT_SCHEMA,
                max_calls=8,
                timeout=600.0,
                tags=("detect",),
            ),
            Tool(
                "findings.list",
                "List findings already registered in this run, filtered by severity or category.",
                findings_list,
                FINDINGS_SCHEMA,
                untrusted_output=False,
                tags=("state",),
            ),
            Tool(
                "endpoints.list",
                "List endpoints known to the asset graph with coverage counters.",
                endpoints_list,
                ENDPOINTS_SCHEMA,
                untrusted_output=False,
                tags=("state",),
            ),
            Tool(
                "payloads.search",
                "Fetch catalogue payloads for a family (xss, sqli, ssti, lfi, ssrf, ...).",
                payloads_search,
                PAYLOAD_SCHEMA,
                untrusted_output=False,
                max_calls=20,
                tags=("catalogue",),
            ),
            Tool(
                "recon.fingerprint",
                "Fingerprint the technologies behind a URL from one response.",
                fingerprint,
                FINGERPRINT_SCHEMA,
                max_calls=10,
                tags=("recon",),
            ),
            Tool(
                "recon.crawl",
                "Crawl from a URL to a bounded depth and page count, registering endpoints.",
                crawl,
                CRAWL_SCHEMA,
                max_calls=4,
                timeout=300.0,
                tags=("recon",),
            ),
            Tool(
                "facts.add",
                "Record a fact with its provenance and confidence so later steps can rely on it.",
                facts_add,
                FACT_SCHEMA,
                untrusted_output=False,
                max_calls=60,
                tags=("memory",),
            ),
            Tool(
                "goal.prove",
                "Attempt to close the goal using non-target facts; refused facts are reported with the reason.",
                prove_goal,
                PROVE_SCHEMA,
                untrusted_output=False,
                max_calls=4,
                tags=("proof",),
            ),
            Tool(
                "notes.write",
                "Write a note, hypothesis, open question or todolist item to the shared blackboard.",
                notes_write,
                NOTE_SCHEMA,
                untrusted_output=False,
                max_calls=40,
                tags=("memory",),
            ),
            Tool(
                "evidence.capture",
                "Persist the last observation as an evidence artefact with a digest.",
                evidence_capture,
                {"type": "object", "properties": {}},
                untrusted_output=False,
                max_calls=20,
                tags=("evidence",),
            ),
            Tool(
                "http.replay",
                "Re-send a request from this run's history to confirm the result is stable.",
                replay_request,
                REPLAY_SCHEMA,
                max_calls=10,
                tags=("http", "verify"),
            ),
            Tool(
                "finish",
                "End the run with a summary and the work that remains open.",
                finish,
                FINISH_SCHEMA,
                untrusted_output=False,
                max_calls=1,
                tags=("control",),
            ),
            Tool(
                "web.probe",
                "Discover sensitive paths, backup files and advertised methods on a base URL.",
                tool_web_probe,
                PROBE_SCHEMA,
                max_calls=4,
                timeout=300.0,
                tags=("recon", "enumeration"),
            ),
            Tool(
                "api.spec",
                "Fetch an OpenAPI or Swagger document, ingest its operations and report public exposure.",
                tool_api_spec,
                SPEC_SCHEMA,
                max_calls=3,
                timeout=120.0,
                tags=("recon", "api"),
            ),
            Tool(
                "graphql.query",
                "Introspect a GraphQL endpoint or run a narrow query against it.",
                tool_graphql,
                GRAPHQL_SCHEMA,
                max_calls=6,
                timeout=120.0,
                tags=("recon", "api"),
            ),
            Tool(
                "auth.flow",
                "Locate a login form, attempt one bounded login and check session handling.",
                tool_auth_flow,
                AUTH_SCHEMA,
                max_calls=3,
                timeout=120.0,
                tags=("auth", "detect"),
            ),
            Tool(
                "jwt.inspect",
                "Inspect a JWT, try a short secret list and test whether an unsigned token is accepted.",
                tool_jwt_inspect,
                JWT_SCHEMA,
                max_calls=4,
                timeout=120.0,
                tags=("auth", "detect"),
            ),
            Tool(
                "oauth.flow",
                "Read OIDC metadata and test redirect URI matching without leaving scope.",
                tool_oauth_flow,
                OAUTH_SCHEMA,
                max_calls=2,
                timeout=120.0,
                tags=("auth", "recon"),
            ),
            Tool(
                "ws.probe",
                "Check WebSocket endpoints for handshake acceptance and missing origin checks.",
                tool_ws_probe,
                WS_SCHEMA,
                max_calls=2,
                timeout=120.0,
                tags=("recon", "websocket"),
            ),
            Tool(
                "fuzz.run",
                "Run a bounded mutation campaign over discovered parameters and return signals.",
                tool_fuzz_run,
                FUZZ_SCHEMA,
                max_calls=3,
                timeout=420.0,
                tags=("detect", "active"),
            ),
            Tool(
                "exploit.run",
                "Attempt exploit-grade proof for the strongest verified findings and return captured evidence.",
                tool_exploit_run,
                {
                    "type": "object",
                    "properties": {
                        "max_attempts": {"type": "integer", "minimum": 1, "maximum": 8, "default": 3},
                        "min_severity": {"type": "string", "enum": ["critical", "high", "medium"], "default": "high"},
                    },
                    "additionalProperties": False,
                },
                max_calls=4,
                timeout=600.0,
                tags=("exploit", "active", "risky"),
            ),
        ]
    )
