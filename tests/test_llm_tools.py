import json

from candix.llm.attachments import AttachmentSet, chunks, describe, from_har, from_path, from_text, redact, sensitive
from candix.llm.calibration import Calibrator, Label, adjust, deflate, from_findings, inflate, log_loss, pick_threshold, precision_recall, reliability, report
from candix.llm.repair import coerce_bool, coerce_list, coerce_number, instruct_retry, needs_retry, repair_action, repair_arguments, repair_json, repair_ladder
from candix.llm.tool_router import ambiguity, arguments_for, choose, describe_router, ensure_allowed, fallback_chain, phase_of_tool, route

TOOLS = ["recon.crawl", "recon.fingerprint", "graphql.query", "jwt.inspect", "detect.run", "exploit.run", "finish"]


# ------------------------------------------------------------------ router
def test_router_prefers_explicit_keyword():
    choice = choose("introspect the graphql schema", tools=TOOLS)
    assert choice.name == "graphql.query"
    assert choice.reasons


def test_router_phase_hint_and_ranking():
    ranked = route("check for xss across endpoints", tools=TOOLS, phase="detect")
    assert ranked[0].name == "detect.run"
    assert len(ranked) <= 3


def test_router_fallback_chain():
    chain = fallback_chain("prove the token is weak", tools=TOOLS, phase="exploit")
    assert chain[0] == "jwt.inspect"
    assert "exploit.run" in chain


def test_router_allow_deny_and_arguments():
    choice = choose("crawl the site", tools=TOOLS)
    assert ensure_allowed(choice, allowed=["recon.crawl"]).name == "recon.crawl"
    assert ensure_allowed(choice, allowed=["detect.run"]).name == ""
    assert ensure_allowed(choice, allowed=["recon.crawl"], deny=["recon.crawl"]).name == ""
    assert arguments_for("recon.crawl", targets=["http://a"])["max_pages"] == 40
    assert arguments_for("detect.run", targets=["http://a"], intents=2)["limit"] == 2
    assert phase_of_tool("exploit.run") == "exploit"
    assert "| tool | phase |" in describe_router(TOOLS)


def test_router_ambiguity_detection():
    from candix.llm.tool_router import ToolChoice

    tied = [ToolChoice("detect.run", 1.0), ToolChoice("exploit.run", 0.9)]
    assert "tied" in ambiguity(tied)
    assert ambiguity([ToolChoice("detect.run", 2.0), ToolChoice("finish", 0.5)]) == ""
    assert ambiguity([]) == ""


# ------------------------------------------------------------------ calibration
def labels():
    return [Label(0.9, True), Label(0.8, True), Label(0.7, False), Label(0.6, True), Label(0.2, False)]


def test_calibration_metrics():
    stats = reliability(labels())
    assert 0 <= stats["brier"] <= 1
    assert stats["labels"] == 5
    assert log_loss(labels()) > 0
    assert 0 <= pick_threshold(labels(), target_precision=0.9) <= 1
    assert precision_recall(labels(), threshold=0.5)["selected"] == 4.0
    assert "| bin |" in report(labels())


def test_calibrator_monotonic_and_roundtrip(tmp_path):
    calibrator = Calibrator().fit(labels())
    assert calibrator.samples == 5
    values = [calibrator.apply(value) for value in (0.0, 0.4, 0.7, 1.0)]
    assert values == sorted(values)
    path = calibrator.save(tmp_path / "cal.json")
    assert Calibrator.load(path).points == calibrator.points


def test_confidence_adjustment():
    assert inflate(0.8) > 0.8
    assert deflate(0.8) < 0.8
    assert adjust(0.8, verified=True) > 0.8
    assert adjust(0.8, contradicted=True) < 0.8
    assert adjust(0.9, source="inference") < 0.9
    found = from_findings([{"id": "f1", "confidence": 80}], ground_truth={"f1": True})
    assert found[0].confidence == 0.8


# ------------------------------------------------------------------ repair
def test_repair_json_variants():
    assert repair_json('```json\n{"a": 1,}\n```').value == {"a": 1}
    assert repair_json("{a: 1, b: [2, 3,]}").value == {"a": 1, "b": [2, 3]}
    assert repair_json("prose first {\"a\": True} prose after").value == {"a": True}
    assert not repair_json("no json at all").ok


def test_repair_action_and_arguments():
    action = repair_action("I will run detect.run next", tools={"detect.run", "finish"})
    assert action.value["tool"] == "detect.run"
    assert action.steps
    args = repair_arguments('{"urls": ["http://a"], "cap": 3}', allowed={"urls"})
    assert args.value == {"urls": ["http://a"]}
    assert not repair_action("nothing", tools={"finish"}).ok


def test_repair_coercions_and_ladder():
    assert coerce_number("42%") == 42.0
    assert coerce_number("x", default=1.0) == 1.0
    assert coerce_bool("on")
    assert not coerce_bool("no")
    assert coerce_list("a, b") == ["a", "b"]
    assert coerce_list(None) == []
    assert repair_ladder("12", parsers=[lambda text: None if not text.isdigit() else int(text)]) == 12
    assert needs_retry(type("R", (), {"ok": False, "steps": ["a"]})())
    assert "JSON only" in instruct_retry("nope", "invalid", schema="{}")


# ------------------------------------------------------------------ attachments
def test_attachment_from_text_and_redaction():
    attachment = from_text("<html><body><p>hi</p><script>x()</script></body></html>", name="page.html")
    assert attachment.kind == "html"
    assert "script" not in attachment.text
    cleaned, hits = redact("api_key = abcdefghijklmnop1234")
    assert "[redacted]" in cleaned and hits == 1
    assert sensitive(from_text("-----BEGIN RSA PRIVATE KEY-----", name="k.pem"))


def test_attachment_path_and_chunks(tmp_path):
    path = tmp_path / "notes.md"
    path.write_text("# notes\n" + "line\n" * 200, encoding="utf-8")
    attachment = from_path(path)
    assert attachment.source.endswith("notes.md")
    assert attachment.sha256
    parts = chunks(attachment, size=100, overlap=10)
    assert len(parts) > 3
    assert "| file | kind |" in describe([attachment])


def test_attachment_set_budget(tmp_path):
    collection = AttachmentSet(budget=60)
    collection.add(from_text("x " * 400, name="big.txt", max_tokens=600))
    assert collection.tokens > 0
    dropped = collection.trim()
    assert dropped == ["big.txt"]
    assert collection.fits()
    collection.add_path(tmp_path / "small.json") if (tmp_path / "small.json").exists() else None
    assert collection.summary()


def test_har_and_request_log(tmp_path):
    har = tmp_path / "traffic.har"
    har.write_text(json.dumps({"log": {"entries": [{"request": {"method": "GET", "url": "http://a/x"}, "response": {"status": 200}}]}}), encoding="utf-8")
    bundle = from_har(har)
    assert bundle.items[0].kind == "har"
    assert "GET http://a/x" in bundle.items[0].text
