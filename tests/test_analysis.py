from candix.analysis.correlate import correlate, priority_order
from candix.analysis.entropy import shannon_entropy
from candix.analysis.html import HTMLDocument
from candix.analysis.sinks import analyze_document
from candix.core.finding import Finding
from candix.core.severity import Severity


def test_link_and_form_extraction():
    body = '<a href="/a">a</a><a href="http://x/b">b</a><form action="/login" method="post"><input name="u"></form>'
    document = HTMLDocument(body, "http://x/")
    assert "http://x/b" in document.url_links()
    assert document.form_endpoints()
    assert any("login" in form.action for form in document.form_endpoints())


def test_entropy_bounds():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaa") == 0.0
    assert shannon_entropy("abcdefghij") > 2.0


def test_sink_detection():
    analysis = analyze_document("<script>document.write(location.hash)</script>")
    assert "document.write" in analysis["sinks"]
    assert analysis["matches"][0]["kind"] == "dom-xss"


def test_correlation_amplifiers():
    findings = [
        Finding(title="OS command injection", severity=Severity.CRITICAL, detector="rce", category="rce", url="http://a/ping"),
        Finding(title="Exposed .env", severity=Severity.HIGH, detector="exposed", category="exposed", url="http://a/.env"),
    ]
    report = correlate(findings)
    assert report.risk_multiplier > 1.0
    assert report.amplifiers
    assert priority_order(findings)[0].severity is Severity.CRITICAL
