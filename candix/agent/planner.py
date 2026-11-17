"""Goal decomposition: a deterministic planner and an LLM-backed planner."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from candix.agent.assetview import asset_view
from candix.agent.models import Decision, Intent, IntentStatus, Phase
from candix.llm.client import LLMClient
from candix.llm.errors import LLMError
from candix.llm.types import ChatRequest, Message


@dataclass
class PlannerState:
    """The slice of the run a planner is allowed to look at."""

    goal: str
    targets: list[str] = field(default_factory=list)
    phase: Phase = Phase.RECON
    findings: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    blackboard: str = ""
    attempted: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    remaining_turns: int = 0
    exploit_enabled: bool = False
    facts: int = 0
    provable_facts: int = 0
    proofs: int = 0
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    turn: int = 0
    next_targets: list[dict[str, Any]] = field(default_factory=list)
    todos: str = ""

    def to_prompt(self) -> str:
        payload = {
            "goal": self.goal,
            "targets": self.targets,
            "phase": self.phase.value,
            "coverage": self.coverage,
            "findings": self.findings[:12],
            "already_attempted": self.attempted[-12:],
            "blocked": self.blocked[-6:],
            "exploit_enabled": self.exploit_enabled,
            "remaining_turns": self.remaining_turns,
            "facts_recorded": self.facts,
            "provable_facts": self.provable_facts,
            "proofs": self.proofs,
            "endpoints_known": len(self.endpoints),
            "next_targets": self.next_targets[:5],
            "todos": self.todos[-1200:],
            "turn": self.turn,
            "blackboard": self.blackboard[-3000:],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


class HeuristicPlanner:
    """Plans from state alone, so a run works with no model configured.

    The plan is intentionally boring: crawl before probing, probe before
    exploiting, verify before claiming. That ordering is what makes the LLM
    planner useful rather than load-bearing - it can deviate, but the default
    path already finishes the job.
    """

    name = "heuristic"

    def __init__(self, *, max_intents: int = 6) -> None:
        self.max_intents = max_intents

    def _seen(self, state: PlannerState, title: str, tool: str) -> bool:
        signature = f"{tool}:{title}"
        return any(signature == item or item.endswith(title) for item in state.attempted)

    def decide(self, state: PlannerState) -> Decision:
        if not state.targets:
            return Decision("finish", "no targets were provided", confidence=1.0, source=self.name)

        coverage = state.coverage or {}
        endpoints = int(coverage.get("endpoints", 0) or 0)
        findings = state.findings
        attempted = "\n".join(state.attempted)

        if endpoints == 0:
            candidates = [
                Intent(
                    title="Crawl the landing page",
                    description="Discover links, forms and script sources before probing anything.",
                    phase=Phase.RECON,
                    tool="recon.crawl",
                    arguments={"url": state.targets[0], "depth": 1, "max_pages": 15},
                    priority=1.0,
                    tags=("recon",),
                ),
                Intent(
                    title="Fingerprint the stack",
                    description="Identify server, framework and technologies from the landing response.",
                    phase=Phase.RECON,
                    tool="recon.fingerprint",
                    arguments={"url": state.targets[0]},
                    priority=0.9,
                    tags=("recon",),
                ),
            ]
            intents = [item for item in candidates if not self._seen(state, item.title, item.tool)]
            if not intents:
                return Decision(
                    "finish",
                    "reconnaissance already ran and reported no endpoints; the target may be unreachable or the crawl was blocked",
                    confidence=0.6,
                    source=self.name,
                )
            return Decision("plan", "no endpoints known yet; start with reconnaissance", intents, 0.8, self.name)

        if not findings:
            detection = Intent(
                title="Run the detector catalogue",
                description="Execute passive and active detectors against the discovered endpoints.",
                phase=Phase.DETECT,
                tool="detect.run",
                arguments={"include_intrusive": True, "max_findings": 40},
                priority=1.0,
                tags=("detect",),
            )
            intents = [detection]
            if "detect.run" in attempted and endpoints:
                best = next((row for row in state.next_targets if row.get("url")), None)
                if best is not None:
                    intents.append(
                        Intent(
                            title=f"Probe {str(best.get('url', ''))[:70]}",
                            description=(
                                "The catalogue ran and found nothing here; request the highest-scoring endpoint directly "
                                "so the next detection pass has a live sample."
                            ),
                            phase=Phase.DETECT,
                            tool="web.probe",
                            arguments={"url": str(best.get("url", ""))},
                            priority=0.6,
                            tags=("probe",),
                        )
                    )
                else:
                    intents.append(
                        Intent(
                            title="Probe uncovered endpoints",
                            description="Issue a plain request to endpoints the detectors did not touch, to check they are live.",
                            phase=Phase.DETECT,
                            tool="endpoints.list",
                            arguments={"limit": 25},
                            priority=0.5,
                            tags=("state",),
                        )
                    )
            return Decision("plan", "endpoints exist but nothing has been tested", intents, 0.75, self.name)

        risky = [finding for finding in findings if str(finding.get("severity")) in {"critical", "high"}]
        unverified = [finding for finding in findings if not finding.get("verified")]

        if state.exploit_enabled and risky and state.phase is not Phase.EXPLOIT:
            intents = [
                Intent(
                    title="Exploit the strongest findings",
                    description=(
                        "Attempt proof-grade exploitation for verified high-severity findings with the catalogue "
                        "techniques and capture the exchanges that show impact."
                    ),
                    phase=Phase.EXPLOIT,
                    tool="exploit.run",
                    arguments={"max_attempts": 3, "min_severity": "high"},
                    priority=0.9,
                    tags=("exploit",),
                )
            ]
            return Decision("plan", "high-severity findings are ready for a proof attempt", intents, 0.75, self.name)

        if unverified:
            material = [item for item in unverified if str(item.get("severity")) in {"critical", "high", "medium"}]
            batch = material[:3] or unverified[:1]
            intents = [
                Intent(
                    title=f"Re-check {str(item.get('title', 'finding'))[:60]}",
                    description="Send the request again to confirm the finding is stable rather than transient.",
                    phase=Phase.VERIFY,
                    tool="http.request",
                    arguments={
                        "url": str(item.get("url", state.targets[0])),
                        "method": str(item.get("method", "GET")),
                        "max_bytes": 6000,
                        "note": f"verification of {item.get('id', '')}",
                    },
                    priority=0.7 - 0.05 * index,
                    tags=("verify",),
                )
                for index, item in enumerate(batch)
            ]
            return Decision("plan", "material findings need a second observation before they are reported", intents, 0.65, self.name)

        if state.facts < min(3, len(findings)):
            target = findings[min(state.facts, len(findings) - 1)]
            claim = "{severity} {title} is reproducible at {url}".format(
                severity=str(target.get("severity", "")).upper(),
                title=str(target.get("title", "finding")),
                url=str(target.get("url", "")),
            )
            intents = [
                Intent(
                    title="Record the finding as a fact",
                    description="Write the observation into the fact store with its provenance so the goal can be proven from evidence.",
                    phase=Phase.VERIFY,
                    tool="facts.add",
                    arguments={
                        "claim": claim[:380],
                        "source": "tool_output",
                        "confidence": "observed",
                        "subject": str(target.get("url", "")),
                        "evidence": [str(target.get("id", ""))],
                    },
                    priority=0.55,
                    tags=("memory", "proof"),
                )
            ]
            return Decision("plan", "findings are stable; record them as evidence-backed facts", intents, 0.65, self.name)

        if any(item.startswith("goal.prove") for item in state.attempted) and not state.proofs:
            return Decision(
                "finish",
                "a proof was attempted and rejected; the evidence collected does not close the goal",
                confidence=0.7,
                source=self.name,
            )

        if state.provable_facts and not state.proofs:
            intents = [
                Intent(
                    title="Prove the goal from recorded facts",
                    description="Close the goal using facts that did not come from the target itself.",
                    phase=Phase.VERIFY,
                    tool="goal.prove",
                    arguments={"claim": state.goal, "note": "facts recorded during this run"},
                    priority=0.5,
                    tags=("proof",),
                )
            ]
            return Decision("plan", "the evidence base is sufficient; attempt the proof", intents, 0.7, self.name)

        return Decision(
            "finish",
            "every finding is verified and no further work is pending",
            confidence=0.8,
            source=self.name,
        )

    def next_phase(self, state: PlannerState) -> Phase:
        coverage = state.coverage or {}
        if int(coverage.get("endpoints", 0) or 0) == 0:
            return Phase.RECON
        if not state.findings:
            return Phase.DETECT
        if state.exploit_enabled and any(str(item.get("severity")) in {"critical", "high"} for item in state.findings):
            return Phase.EXPLOIT
        return Phase.VERIFY


PLANNER_SYSTEM = """You plan authorized penetration tests. You do not execute tools; you choose the next
small set of intents for a worker that does.

Rules that are not negotiable:
- Every intent must be inside the engagement scope stated in the state.
- Prefer the cheapest action that produces evidence. Crawling before probing, probing before exploiting.
- At most {max_intents} intents per decision. Each needs a tool from the provided list and arguments that
  validate against that tool's schema.
- Never plan destruction, denial of service, persistence or work against hosts outside scope.
- If the goal is already proven, or nothing remains that could change the answer, answer with
  {{"action": "finish", "reasoning": "..."}}.

Reply with JSON only, matching this shape:
{{"action": "plan"|"finish",
  "reasoning": "one or two sentences",
  "confidence": 0.0-1.0,
  "intents": [{{"title": "...", "phase": "recon"|"detect"|"exploit"|"verify"|"report",
               "tool": "tool.name", "arguments": {{}}, "priority": 0.0-1.0, "description": "..."}}]}}
"""


class LLMPlanner:
    """Plans with a model, validated against the real tool schemas.

    Any failure - transport, JSON, unknown tool, invalid arguments - falls back
    to the heuristic plan for that turn, so a broken model degrades the run
    instead of stopping it.
    """

    name = "llm"

    def __init__(
        self,
        client: LLMClient,
        *,
        tool_names: Iterable[str],
        schemas: dict[str, dict[str, Any]] | None = None,
        fallback: HeuristicPlanner | None = None,
        max_intents: int = 5,
        temperature: float = 0.2,
    ) -> None:
        self.client = client
        self.tool_names = sorted(tool_names)
        self.schemas = dict(schemas or {})
        self.fallback = fallback or HeuristicPlanner()
        self.max_intents = max_intents
        self.temperature = temperature
        self.last_error = ""

    # ------------------------------------------------------------------
    def _seen(self, state: PlannerState, title: str, tool: str) -> bool:
        signature = f"{tool}:{title}"
        return any(signature == item or item.endswith(title) for item in state.attempted)

    def decide(self, state: PlannerState) -> Decision:
        try:
            decision = self._decide_with_model(state)
        except Exception as error:  # a broken provider must not end the run
            self.last_error = str(error) or type(error).__name__
            decision = self.fallback.decide(state)
            decision.reasoning = f"{decision.reasoning} (model planner unavailable: {self.last_error[:120]})"
            decision.source = "heuristic-fallback"
        if decision.action == "plan" and not decision.intents:
            decision = self.fallback.decide(state)
            decision.source = "heuristic-fallback"
        return decision

    def _decide_with_model(self, state: PlannerState) -> Decision:
        messages = [
            Message.system(PLANNER_SYSTEM.format(max_intents=self.max_intents)),
            Message.user("Current state:\n" + state.to_prompt() + "\nAvailable tools:\n" + "\n".join(f"- {name}" for name in self.tool_names)),
        ]
        request = ChatRequest(messages=messages, model="", temperature=self.temperature, max_tokens=1200)
        payload, _response = self.client.complete_json(request, task="plan")
        action = str(payload.get("action", "plan")).lower()
        reasoning = str(payload.get("reasoning", ""))[:600]
        confidence = float(payload.get("confidence", 0.5) or 0.5)
        if action == "finish":
            return Decision("finish", reasoning or "model decided the goal is complete", confidence=confidence, source=self.name)
        intents: list[Intent] = []
        problems: list[str] = []
        for item in (payload.get("intents") or [])[: self.max_intents]:
            if not isinstance(item, dict):
                continue
            tool = str(item.get("tool", ""))
            if tool not in self.tool_names:
                problems.append(f"unknown tool {tool!r}")
                continue
            arguments = item.get("arguments") or {}
            if not isinstance(arguments, dict):
                problems.append(f"{tool}: arguments must be an object")
                continue
            schema = self.schemas.get(tool)
            if schema:
                from candix.llm.jsonschema import coerced

                arguments, errors = coerced(arguments, schema)
                if errors:
                    problems.append(f"{tool}: {errors[0]}")
                    continue
            try:
                phase = Phase(str(item.get("phase", "detect")))
            except ValueError:
                phase = Phase.DETECT
            intents.append(
                Intent(
                    title=str(item.get("title") or f"Use {tool}")[:120],
                    description=str(item.get("description", ""))[:400],
                    phase=phase,
                    tool=tool,
                    arguments=dict(arguments),
                    priority=max(0.0, min(1.0, float(item.get("priority", 0.5) or 0.5))),
                    origin=self.name,
                )
            )
        if not intents:
            raise ValueError("model produced no usable intents" + (f": {'; '.join(problems)}" if problems else ""))
        return Decision("plan", reasoning or "model plan", intents, confidence, self.name)


def phase_for_intents(intents: Iterable[Intent]) -> Phase:
    ordered = [intent.phase for intent in intents]
    if not ordered:
        return Phase.RECON
    for phase in (Phase.EXPLOIT, Phase.VERIFY, Phase.DETECT, Phase.RECON, Phase.REPORT):
        if phase in ordered:
            return phase
    return ordered[0]


def describe_decision(decision: Decision) -> str:
    if decision.action == "finish":
        return f"finish — {decision.reasoning}"
    titles = "; ".join(intent.title for intent in decision.intents)
    return f"plan({len(decision.intents)}) — {titles}"
