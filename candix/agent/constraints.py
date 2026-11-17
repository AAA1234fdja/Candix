"""Operation constraints block — ported from engine/agent/constraints.go."""

from __future__ import annotations


def constraint_block(constraints: list[dict] | None) -> str:
    if not constraints:
        return ""
    allow: list[str] = []
    deny: list[str] = []
    for c in constraints:
        text = (c.get("text") or c.get("value") or "").strip()
        if not text:
            continue
        kind = c.get("kind", "")
        if kind == "allow":
            allow.append(f"- {text}")
        else:
            deny.append(f"- {text}")
    if not allow and not deny:
        return ""
    b: list[str] = []
    b.append("\n\n[Operation constraints (highest priority, above every exploration/expansion heuristic below; before generating any intent or executing any action you must first self-check for violations — if it violates a constraint, do not proceed)]:")
    if allow:
        b.append("Allowed operations:\n" + "\n".join(allow))
    if deny:
        b.append("Forbidden operations:\n" + "\n".join(deny))
    b.append("(Discovering a new target/port/host outside the constraints does not grant authorization: unless it falls within the allowed range above, record it as an out-of-scope fact and skip it — do not spawn intents or execute actions for it.)")
    return "\n".join(b)


def load_constraints_from_exploration(exploration) -> list[dict]:
    """Best-effort extractor for in-memory exploration graphs."""
    if exploration is None:
        return []
    # Try several shapes: list_constraints(), constraints attr, nodes
    try:
        if hasattr(exploration, "list_constraints"):
            return list(exploration.list_constraints() or [])
    except Exception:
        pass
    try:
        if hasattr(exploration, "constraints"):
            v = exploration.constraints
            if isinstance(v, list):
                return v
    except Exception:
        pass
    return []
