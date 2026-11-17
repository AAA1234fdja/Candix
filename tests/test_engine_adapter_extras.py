from candix.engine_adapter.enrich import EnrichEngine
from candix.engine_adapter.notify_ext import NotifyDispatcher, kinds, valid_kind
from candix.engine_adapter.report import ReportEngine
from candix.engine_adapter.mcp_bridge import McpRegistry
from candix.engine_adapter.sidequestion import SideQuestionService
from candix.engine_adapter.llmrec import LlmRecorder
from candix.engine_adapter.extension import ExtensionBridge
from candix.engine_adapter import Engine

def test_enrich_sync():
    e = EnrichEngine()
    r = e.resolve_domain_sync(1, "localhost")
    assert "host" in r
    r2 = e.probe_site_sync(2, "https://example.com")
    assert r2["url"] == "https://example.com"
    e.close()

def test_notify_kinds():
    assert "webhook" in kinds()
    assert valid_kind("dingtalk")
    assert not valid_kind("unknown123")
    d = NotifyDispatcher([])
    r = d.dispatch(type("M", (), {"title": "t", "body": "b", "severity": "info", "findings": []})())
    assert r == []

def test_report_markdown():
    eng = ReportEngine()
    md = eng.markdown(title="Test", goal="goal", findings=[{"name": "XSS", "severity": "high", "summary": "x"}])
    assert "# Penetration Test Report" in md
    assert "XSS" in md

def test_mcp_registry():
    reg = McpRegistry()
    assert reg.all_tools() == []
    reg.close_all()

def test_sidequestion_no_provider():
    svc = SideQuestionService(provider=None)
    ans = svc.answer([{"role": "user", "content": "hi"}])
    assert ans.text

def test_llmrec():
    rec = LlmRecorder(model="test", profile_name="default")
    rec.complete([{"role": "user", "content": "hi"}], task_id="1")
    assert len(rec.records) == 1
    assert len(rec.usages) == 1

def test_extension_bridge():
    br = ExtensionBridge()
    sess = br.register_session("s1", "t1")
    assert sess.id == "s1"
    req = br.capture("s1", "https://example.com")
    assert req is not None
    assert len(br.get_requests("s1")) == 1
    assert br.snapshot()["sessions"] == 1

def test_engine_includes_extras():
    eng = Engine.from_env()
    h = eng.health()
    assert hasattr(h, "enrich")
    assert hasattr(h, "notify")
    assert hasattr(h, "report")
    assert hasattr(h, "mcp")
    assert hasattr(h, "extension")
    d = eng.to_dict()
    assert "enrich" in d
    assert "mcp" in d
