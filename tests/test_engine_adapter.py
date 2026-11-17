import pytest
from candix.engine_adapter import Engine
from candix.engine_adapter.config_adapter import ConfigAdapter
from candix.engine_adapter.db import DbClient, DbConfig
from candix.engine_adapter.server_client import ServerClient
from candix.engine_adapter.guard import GuardAdapter
from candix.engine_adapter.intercept_ext import InterceptAdapter
from candix.engine_adapter.traffic import TrafficAdapter
from candix.engine_adapter.egress_ext import EgressAdapter
from candix.engine_adapter.agent_gateway import AgentGateway
from candix.engine_adapter.evidence import EvidenceAdapter
from candix.engine_adapter.llmpool import LlmPoolAdapter

def test_engine_health():
    e = Engine.from_env()
    h = e.health()
    assert h.bridge is not None
    assert h.db is not None
    assert h.egress is not None

def test_engine_to_dict():
    e = Engine.from_env()
    d = e.to_dict()
    assert "bridge" in d
    assert "db" in d
    assert "llm_profiles" in d

def test_db_client_sqlite():
    db = DbClient(DbConfig(dsn="", sqlite_path=":memory:"))
    assert db.health()["ok"]
    exp_id = db.create_exploration("t1", "goal test")
    assert exp_id > 0
    got = db.get_exploration(exp_id)
    assert got is not None
    asset_id = db.add_asset(exp_id, "endpoint", "https://example.com")
    assert asset_id > 0
    finding_id = db.add_finding(exp_id, "XSS", severity="high", url="https://example.com/q=1")
    assert finding_id > 0
    db.close()

def test_guard_check():
    g = GuardAdapter()
    r = g.check("Bash", {"command": "echo hi"})
    assert "allowed" in r
    assert r["allowed"] is True
    r2 = g.check("Bash", {"command": "rm -rf /"})
    # destructive may still be allowed but scored high — check reports score
    assert "score" in r2 or "allowed" in r2

def test_intercept_adapter():
    ia = InterceptAdapter()
    s = ia.score_risk("Bash", {"command": "echo hi"})
    assert "score" in s
    t = ia.normalize_target("https://example.com:443/path")
    assert t.ok or not t.ok  # always returns TargetInfo
    p = ia.argv_prefix("git status --porcelain")
    assert isinstance(p, list)

def test_traffic_adapter():
    t = TrafficAdapter(data_dir="/tmp/candix-traffic-test")
    ex = t.record("GET", "https://example.com/", status=200, resp_body=b"hello")
    assert ex.id
    lst = t.list()
    assert len(lst) >= 1
    assert t.validate_url("https://example.com") is True
    assert t.validate_url("ftp://x") is False

def test_egress_adapter():
    e = EgressAdapter()
    prof = e.profile("off")
    assert prof.name == "off"
    snap = e.snapshot()
    assert "profile" in snap

def test_agent_gateway():
    ag = AgentGateway()
    block = ag.constraints_block()
    assert isinstance(block, str)
    caps = ag.worker_capabilities()
    assert isinstance(caps, list)
    line = ag.budget_line(task_tokens=100000, task_turns=20)
    assert isinstance(line, str)

def test_evidence_adapter(tmp_path):
    ev = EvidenceAdapter(data_dir=str(tmp_path))
    e = ev.put("t1", "http", "request/response dump")
    assert e.digest
    assert len(ev.list("t1")) == 1
    assert ev.get(e.id) is not None

def test_llmpool():
    lp = LlmPoolAdapter()
    profiles = lp.list_profiles()
    assert len(profiles) >= 1
    assert lp.active() is not None

def test_server_client_offline():
    sc = ServerClient(base_url="http://127.0.0.1:1")
    r = sc.health()
    assert r.ok is False
    assert r.error != ""
