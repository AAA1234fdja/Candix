import json

from candix.llm.agentic import (
    compress_observations,
    confidence_from_evidence,
    critique,
    is_actionable,
    narrow,
    parse_trace,
    reflection_questions,
    repair_plan,
)
from candix.llm.conversation import Conversation, estimate, transcript


# ------------------------------------------------------------------ conversation
def test_conversation_appends_and_counts():
    conversation = Conversation(system="you are an agent", max_tokens=2000)
    conversation.user("hello")
    conversation.assistant("hi", tool_calls=[{"name": "http.request", "arguments": {"url": "http://a"}}])
    conversation.tool("http.request", "200 OK")
    assert len(conversation) == 4
    assert conversation.tokens > 0
    assert conversation.last("tool").content == "200 OK"
    assert estimate(conversation)["tool_turns"] == 1


def test_conversation_compacts_until_it_fits():
    conversation = Conversation(system="rules", max_tokens=420, reserve_output=80)
    for index in range(8):
        conversation.user(f"question {index} " + "x" * 200)
        conversation.tool("http.request", "y" * 400)
    before = conversation.tokens
    info = conversation.compact(keep_last=4)
    assert info["compacted"]
    assert conversation.tokens < before
    assert conversation.budget_left() >= 0
    assert conversation.summary
    assert conversation.compactions == 1


def test_conversation_fit_reports_shrinkage():
    conversation = Conversation(system="rules", max_tokens=300, reserve_output=60)
    conversation.user("u" * 2000)
    result = conversation.fit()
    assert result["truncated"] or result["dropped"] or result["estimated_tokens"] <= 300


def test_conversation_roundtrip(tmp_path):
    conversation = Conversation(system="rules", max_tokens=1000)
    conversation.user("hello")
    conversation.assistant("thinking", tool_calls=[{"name": "facts.add", "arguments": {}}])
    path = conversation.save(tmp_path / "conversation.json")
    loaded = Conversation.load(path)
    assert len(loaded) == len(conversation)
    assert loaded.turns[-1].tool_calls[0]["name"] == "facts.add"
    assert "user: hello" in transcript(conversation)


def test_conversation_fork_keeps_recent_turns():
    conversation = Conversation(system="rules")
    for index in range(5):
        conversation.user(f"message {index}")
    clone = conversation.fork(keep_last=2)
    assert len(clone) == 3
    assert clone.turns[-1].content == "message 4"


def test_conversation_drop_tools():
    conversation = Conversation()
    conversation.user("q")
    conversation.tool("http.request", "r")
    assert conversation.drop_tools() == 1
    assert all(turn.role != "tool" for turn in conversation.turns)


# ------------------------------------------------------------------ agentic
def test_parse_trace_extracts_steps():
    text = (
        "Thought: the login form needs a CSRF token\n"
        "Action: http.request\n"
        "Observation: 200 OK with form\n"
        "Final answer: token found"
    )
    trace = parse_trace(text)
    assert trace.actions == ["http.request"]
    assert "CSRF" in trace.steps[0].thought
    assert trace.final == "token found"
    assert trace.to_dict()["steps"]


def test_is_actionable_checks_tool_and_arguments():
    assert is_actionable({"tool": "a.b", "arguments": {}}, ["a.b"])[0]
    ok, problems = is_actionable({"tool": "zzz", "arguments": "nope"}, ["a.b"])
    assert not ok
    assert len(problems) == 2


def test_repair_plan_drops_bad_steps():
    text = json.dumps(
        {
            "intents": [
                {"tool": "http.request", "arguments": {"url": "http://a"}},
                {"tool": "made.up", "arguments": {}},
                {"tool": "facts.add", "arguments": "bad"},
            ]
        }
    )
    steps = repair_plan(text, ["http.request", "facts.add"])
    assert [step["tool"] for step in steps] == ["http.request"]


def test_narrow_reduces_expensive_arguments():
    step = {"tool": "recon.crawl", "arguments": {"max_pages": 40, "urls": ["a", "b", "c", "d"]}}
    narrowed = narrow(step, reason="timeout")
    assert narrowed["arguments"]["max_pages"] == 20
    assert len(narrowed["arguments"]["urls"]) == 2
    assert narrowed["retry"]
    assert "retry after" in narrowed["arguments"]["note"]
    assert step["arguments"]["max_pages"] == 40


def test_critique_flags_unsupported_claims():
    strong = critique("The endpoint is confirmed exploitable.", evidence_refs=0)
    assert strong.overclaimed
    assert not strong.acceptable()
    supported = critique("Impact: any user record can be read. The response contained another user's email.", evidence_refs=2)
    assert supported.acceptable()
    assert not supported.issues or "impact" not in " ".join(supported.issues)


def test_confidence_mapping():
    assert confidence_from_evidence(0) == "possible"
    assert confidence_from_evidence(1) == "likely"
    assert confidence_from_evidence(2, reproduced=True) == "confirmed"


def test_reflection_questions_target_missing_proofs():
    trace = parse_trace("Thought: x\nAction: detect.run")
    questions = reflection_questions(trace, findings=2, proofs=0)
    assert any("proof" in question.lower() for question in questions)


def test_compress_observations_deduplicates():
    text = compress_observations(["200 OK\nbody", "200 OK\nbody", "404 not found"])
    assert text.count("200 OK") == 1
    assert "404" in text
