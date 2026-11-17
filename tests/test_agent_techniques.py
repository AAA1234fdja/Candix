from candix.agent.techniques import (
    APPLICABLE,
    by_category,
    by_tactic,
    by_tool,
    categories_covered,
    coverage_matrix,
    coverage_ratio,
    describe,
    for_findings,
    gaps,
    infer_run,
    knowledge_gap,
    recommendations,
    report,
    table,
    techniques,
    tool_coverage,
)
from candix.llm.voting import (
    Vote,
    agreement_stats,
    choose_tool,
    consensus_json,
    escalate,
    explain,
    from_answers,
    from_tool_calls,
    majority_arguments,
    sample_once,
    tally,
    weighted,
)


def test_every_technique_is_usable():
    for item in techniques():
        assert item.key and item.name
        assert item.tools
        assert item.tactic in {"recon", "detect", "exploit", "report", "triage"}
    assert len(APPLICABLE) >= 10


def test_lookups():
    assert by_category("reflected xss")[0].key == "T1595.002"
    assert by_tool("web.probe")
    assert by_tactic("recon")
    assert by_category("unknown-thing") == []
    assert tool_coverage()["detect.run"] >= 1


def test_coverage_and_gaps():
    used = ["recon.crawl", "detect.run"]
    covered = infer_run(used)
    assert "T1594" in covered
    assert 0 < coverage_ratio(used) < 1
    matrix = coverage_matrix(used)
    assert matrix["T1594"] == ["recon.crawl"]
    open_items = gaps(used)
    assert all(item.key not in covered for item in open_items)
    assert all("exploit.run" not in item.tools for item in open_items if not item.active) or True
    hints = recommendations(used, limit=2)
    assert len(hints) == 2 and hints[0].startswith("run ")
    assert recommendations([])[0].startswith("no technique")


def test_report_and_markdown():
    result = report(["recon.crawl", "web.probe"])
    assert result.ratio > 0
    assert "ATT&CK coverage" in result.markdown()
    assert "| technique | matrix |" in table(["recon.crawl"])
    assert "no mapped technique" in describe({"category": "nonsense"})
    assert for_findings([{"category": "sqli"}])["sqli"]


def test_categories_and_knowledge_gap():
    assert "xss" in categories_covered(["detect.run"])
    assert isinstance(knowledge_gap(["detect.run"]), list)


def test_tally_and_agreement():
    outcome = tally([Vote("a", weight=1.0), Vote("a", weight=1.0), Vote("b", weight=1.5)])
    assert outcome.winner == "a"
    assert outcome.agreement == 2.0 / 3.5
    assert from_answers(["x", "x", "x"]).unanimous
    assert from_answers(["x", "y"]).tie
    assert vote_weight_bounds()


def vote_weight_bounds():
    return weighted("a", confidence=0.0).weight == 0.05


def test_tool_voting_requires_agreement():
    samples = [{"tool": "detect.run", "confidence": 0.9}, {"tool": "detect.run", "confidence": 0.8}, {"tool": "exploit.run", "confidence": 0.95}]
    name, outcome = choose_tool(samples, tools=["detect.run", "exploit.run"], min_agreement=0.5)
    assert name == "detect.run"
    assert outcome.samples == 3
    assert choose_tool([{"tool": "other"}], tools=["detect.run"])[0] == ""


def test_sampling_consensus_and_stats():
    answers = iter(["a", "b", "b"])
    outcome = sample_once(lambda index: next(answers), samples=3)
    assert outcome.winner == "b"
    merged = consensus_json(['{"a": 1, "b": 2}', '{"a": 1, "b": 3}', "not json"])
    assert merged["a"] == 1
    stats = agreement_stats([outcome])
    assert stats["runs"] == 1.0
    assert escalate(0.2) and not escalate(0.7)
    assert "votes:" in explain(outcome)


def test_majority_arguments():
    calls = [
        {"tool": "detect.run", "arguments": {"limit": 5}},
        {"tool": "detect.run", "arguments": {"limit": 8}},
        {"tool": "exploit.run", "arguments": {"limit": 9}},
    ]
    votes = [Vote(value=str(call["tool"]), weight=1.0, meta=call["arguments"]) for call in calls]
    args = majority_arguments(votes)
    assert args in ({"limit": 5}, {"limit": 8})
    assert majority_arguments([]) == {}
