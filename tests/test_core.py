import pytest

from candix.core import severity
from candix.core.config import Config
from candix.core.errors import ParseError
from candix.core.redact import redact_text
from candix.core.scope import Engagement, build_authorization
from candix.net.url import URL, join_url


def test_cvss_scoring():
    vector = severity.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert vector.score == 9.8
    assert vector.severity is severity.Severity.CRITICAL
    assert 0.0 <= severity.CVSS().score <= 10.0


def test_severity_ordering():
    assert severity.Severity.CRITICAL.rank > severity.Severity.LOW.rank > severity.Severity.INFO.rank
    assert severity.Severity.parse("HIGH") is severity.Severity.HIGH
    with pytest.raises(ParseError):
        severity.Severity.parse("nonsense")


def test_url_parsing():
    url = URL.parse("HTTP://Example.COM:8080/b?x=1#frag")
    assert url.host == "example.com"
    assert url.port == 8080
    assert join_url("http://a", "/b").render() == "http://a/b"
    assert join_url(URL.parse("http://a/x"), "../y").render() == "http://a/y"


def test_redaction():
    text = redact_text("Authorization: Bearer abcdef123456 and password=hunter2")
    assert "abcdef123456" not in text
    assert "hunter2" not in text


def test_authorization_scope():
    document = build_authorization(
        engagement="t", client="unit", operator="tester", authorized_by="owner", include=["localhost:8080"], allow_exploit=True
    )
    engagement = Engagement.from_document(document)
    assert engagement.guard_url("http://localhost:8080/x").host == "localhost"
    with pytest.raises(Exception):
        engagement.guard_url("http://localhost:9999/x")


def test_config_profiles():
    assert Config.profile("lab").get("exploit.enabled") is True
    with pytest.raises(Exception):
        Config.profile("does-not-exist")
