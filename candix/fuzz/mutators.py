"""Value mutators grouped into families the scheduler can weigh independently."""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from typing import Callable, Iterable

from candix.catalog.payloads import get_payloads

FAMILIES = ("boundary", "injection", "encoding", "structural", "chaos", "protocol")

STRATEGY_WEIGHTS: dict[str, dict[str, float]] = {
    "balanced": {"boundary": 0.25, "injection": 0.3, "encoding": 0.2, "structural": 0.15, "chaos": 0.1},
    "boundary": {"boundary": 0.7, "encoding": 0.15, "structural": 0.15},
    "injection": {"injection": 0.65, "encoding": 0.25, "boundary": 0.1},
    "encoding": {"encoding": 0.7, "injection": 0.15, "boundary": 0.15},
    "structural": {"structural": 0.6, "boundary": 0.2, "encoding": 0.2},
    "chaos": {"chaos": 0.6, "encoding": 0.2, "boundary": 0.2},
}

INJECTION_SOURCES = ("sqli", "xss", "ssti", "lfi", "cmdi", "open_redirect", "crlf", "nosqli", "ldap", "xpath", "ssrf")

_BOUNDARY = (
    "",
    " ",
    "-1",
    "0",
    "1",
    "2147483647",
    "-2147483648",
    "9223372036854775807",
    "1e309",
    "NaN",
    "Infinity",
    "0000000001",
    "1.0000000001",
    "True",
    "False",
    "null",
    "undefined",
    "[]",
    "{}",
    "a" * 4096,
    "9" * 128,
)

_ENCODING = (
    "%00",
    "%0a",
    "%0d%0a",
    "%2e%2e%2f",
    "%252e%252e%252f",
    "..%5c..%5c",
    "%uff1cscript%uff1e",
    "\\u003cscript\\u003e",
    "&#x3c;script&#x3e;",
    "&lt;script&gt;",
    "\u0000",
    "\r\n",
    "%c0%ae%c0%ae/",
    "%%30%30",
    "%2f%2e%2e/",
    "\u202e\u0074\u0078\u0074",
)

_STRUCTURAL = (
    '{"$ne": null}',
    '{"$gt": ""}',
    '[{"$match": {}}]',
    '{"__proto__": {"polluted": true}}',
    "a=1&b=2",
    "1;2",
    "1|2",
    "1&&2",
    "1||2",
    "__proto__[polluted]=1",
    "constructor[prototype][polluted]=1",
    "<%= 7*7 %>",
    "${7*7}",
    "{{7*7}}",
    "#{7*7}",
    "@(7*7)",
)

_CHAOS = (
    "\ud83d\udca9",
    "\u2603" * 32,
    "A" * 8192,
    "".join(random.Random(7).choice(string.printable) for _ in range(256)).strip(),
    "../../../../../../../../etc/hostname",
    "$(id)",
    "`id`",
    "|id",
    ";id",
    "' OR '1'='1",
)

_ERROR_PROBES = (
    "{",
    "[",
    "'",
    '"',
    "\\",
    "<",
    ">",
    "&",
    "%",
    "{{",
    "${",
)


@dataclass(frozen=True)
class Mutation:
    value: str
    family: str
    label: str

    @property
    def is_control(self) -> bool:
        return self.family == "boundary" and self.label.startswith("identical")


def _dedupe(items: Iterable[Mutation]) -> list[Mutation]:
    seen: set[tuple[str, str]] = set()
    result: list[Mutation] = []
    for item in items:
        key = (item.value, item.family)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def boundary_mutations(original: str) -> list[Mutation]:
    values = [Mutation(original, "boundary", "identical"), Mutation(original + "x", "boundary", "appended")]
    for value in _BOUNDARY:
        values.append(Mutation(value, "boundary", f"boundary:{value[:24] or 'empty'}"))
    for probe in _ERROR_PROBES:
        values.append(Mutation(original + probe, "boundary", f"delimiter:{probe}"))
    return _dedupe(values)


def encoding_mutations(original: str) -> list[Mutation]:
    values = [Mutation(original + value, "encoding", f"append:{value[:20]}") for value in _ENCODING]
    values += [Mutation(f"{original}{value}", "encoding", f"prefix:{value[:20]}") for value in _ENCODING[:6]]
    return _dedupe(values)


def structural_mutations(original: str) -> list[Mutation]:
    values = [Mutation(value, "structural", f"structure:{value[:28]}") for value in _STRUCTURAL]
    values += [
        Mutation(f"{original}{value}", "structural", f"mixed:{value[:20]}") for value in _STRUCTURAL[:6]
    ]
    values += [
        Mutation(f"{original}&{value}" if "=" in value else value, "structural", f"param:{value[:20]}")
        for value in _STRUCTURAL[:4]
    ]
    return _dedupe(values)


def chaos_mutations(original: str, rng: random.Random | None = None) -> list[Mutation]:
    generator = rng or random.Random(1234)
    values = [Mutation(value, "chaos", f"chaos:{index}") for index, value in enumerate(_CHAOS)]
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{};:'\",.<>/?\\|`~"
    for _ in range(12):
        length = generator.choice((8, 32, 128, 512))
        values.append(Mutation("".join(generator.choice(alphabet) for _ in range(length)), "chaos", "chaos:random"))
    values.append(Mutation(original * generator.choice((2, 8, 32)), "chaos", "chaos:repeat"))
    return _dedupe(values)


def injection_mutations(original: str, *, limit: int = 24, families: Iterable[str] = INJECTION_SOURCES) -> list[Mutation]:
    values: list[Mutation] = []
    for name in families:
        try:
            payloads = get_payloads(name)
        except KeyError:
            continue
        for payload in payloads[: max(1, limit // max(1, len(INJECTION_SOURCES)) + 1)]:
            values.append(Mutation(payload, "injection", f"inject:{name}"))
    return _dedupe(values)


GENERATORS: dict[str, Callable[[str], list[Mutation]]] = {
    "boundary": boundary_mutations,
    "encoding": encoding_mutations,
    "structural": structural_mutations,
    "chaos": chaos_mutations,
    "injection": injection_mutations,
}


def mutations_for(
    original: str,
    strategy: str = "balanced",
    *,
    rng: random.Random | None = None,
    limit: int | None = None,
) -> list[Mutation]:
    """Build the mutation list for one parameter, honouring the strategy mix."""

    weights = STRATEGY_WEIGHTS.get(strategy, STRATEGY_WEIGHTS["balanced"])
    mutations: list[Mutation] = []
    for family, weight in weights.items():
        generator = GENERATORS.get(family)
        if generator is None:
            continue
        produced = generator(original)
        if family == "chaos":
            produced = chaos_mutations(original, rng)
        budget = max(1, int(round(len(produced) * weight + 1)))
        mutations.extend(produced[:budget])
    unique = _dedupe(mutations)
    if limit is not None and len(unique) > limit:
        generator = rng or random.Random(len(original))
        keep = unique[:2]
        pool = unique[2:]
        keep.extend(generator.sample(pool, min(len(pool), max(0, limit - len(keep)))))
        unique = _dedupe(keep)
    return unique


STRATEGY_DESCRIPTIONS = {
    "balanced": "even mix of boundary, injection, encoding and structural probes",
    "boundary": "extremes, empty values, delimiters and oversized input",
    "injection": "catalogue payloads for SQL, template, command, file and script sinks",
    "encoding": "double encoding, null bytes, unicode and CRLF transformations",
    "structural": "JSON, array, operator and prototype shape changes",
    "chaos": "random bytes, repetition and oversized garbage",
}


def describe_strategies() -> dict[str, str]:
    return dict(STRATEGY_DESCRIPTIONS)
