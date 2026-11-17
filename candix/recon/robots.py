"""robots.txt parsing."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RobotsRules:
    disallow: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    crawl_delay: float | None = None
    comments: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)

    def allowed(self, path: str, user_agent: str = "candix") -> bool:
        best_match = -1
        allowed = True
        for rule in self.disallow:
            if rule and path.startswith(rule) and len(rule) > best_match:
                best_match = len(rule)
                allowed = False
        for rule in self.allow:
            if rule and path.startswith(rule) and len(rule) >= best_match:
                best_match = len(rule)
                allowed = True
        return allowed

    def to_dict(self) -> dict[str, object]:
        return {
            "disallow": list(self.disallow),
            "allow": list(self.allow),
            "sitemaps": list(self.sitemaps),
            "crawl_delay": self.crawl_delay,
        }


def parse_robots(text: str) -> RobotsRules:
    rules = RobotsRules()
    current_agents: list[str] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.split("#", 1)
        if len(line) > 1 and line[1].strip():
            rules.comments.append(line[1].strip())
        content = line[0].strip()
        if not content or ":" not in content:
            continue
        key, _, value = content.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            current_agents.append(value)
            if value and value != "*":
                rules.user_agents.append(value)
        elif key in {"disallow", "allow"}:
            if value:
                getattr(rules, key).append(value)
        elif key == "sitemap":
            if value:
                rules.sitemaps.append(value)
        elif key == "crawl-delay":
            try:
                rules.crawl_delay = float(value)
            except ValueError:
                continue
    rules.disallow = list(dict.fromkeys(rules.disallow))
    rules.allow = list(dict.fromkeys(rules.allow))
    return rules


def interesting_paths(rules: RobotsRules) -> list[str]:
    return [path for path in rules.disallow if path and path != "/"][:100]
