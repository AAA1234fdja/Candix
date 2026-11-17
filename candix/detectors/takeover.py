"""Subdomain takeover indicators."""

from __future__ import annotations

from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector
from candix.net import dns

_PROVIDER_SIGNATURES = (
    ("amazonaws.com", ("nosuchbucket", "the specified bucket does not exist", "no such bucket")),
    ("github.io", ("there isn't a github pages site here", "404 there is no site here")),
    ("herokuapp.com", ("no such app", "heroku | no such app", "there is no app configured at that hostname")),
    ("azurewebsites.net", ("404 web site not found", "site not found")),
    ("cloudfront.net", ("bad request", "the request could not be satisfied")),
    ("readthedocs.io", ("unknown domain", "there is no site configured at this address")),
    ("surge.sh", ("project not found",)),
    ("bitbucket.io", ("repository not found",)),
    ("pages.dev", ("project not found",)),
    ("vercel.app", ("deployment not found", "the deployment could not be found")),
    ("netlify.app", ("not found - request id",)),
    ("ngrok.io", ("tunnel", "endpoint is offline")),
)


@register_detector
class SubdomainTakeoverDetector(BaseDetector):
    meta = DetectorMeta(
        id="takeover",
        name="Subdomain takeover",
        category="takeover",
        description="Follows CNAME chains to known providers and checks for unclaimed-resource error pages.",
        severity=Severity.HIGH,
        cwe=("CWE-350",),
        owasp=("A05:2021 Security Misconfiguration",),
        intrusive=False,
        tags=("dns", "subdomain"),
        order=185,
        remediation_key="takeover",
    )

    def run(self) -> Iterable[Finding]:
        hosts: set[str] = set()
        for target in self.ctx.targets:
            hosts.add(target.host)
        if self.ctx.config.get("scan.include_subdomains", False):
            from candix.recon.subdomains import enumerate_subdomains

            hosts.update(enumerate_subdomains(self.ctx.primary_target.host, limit=100))
        for host in sorted(hosts):
            if self.ctx.scope is not None and not any(self.ctx.scope.matches(f"https://{candidate}/") for candidate in (host,)):
                continue
            finding = self._check(host)
            if finding is not None:
                yield self.emit(finding)

    def _check(self, host: str) -> Finding | None:
        chain = dns.cname_chain(host)
        if not chain:
            return None
        target = chain[-1]
        provider = next((name for name, _ in _PROVIDER_SIGNATURES if name in target), "")
        if not provider:
            return None
        try:
            response = self.http.get(f"https://{host}/", tag="takeover", allow_redirects=False)
        except Exception:
            return None
        body = response.text.lower()
        markers = next(signature for name, signature in _PROVIDER_SIGNATURES if name == provider)
        matched = next((marker for marker in markers if marker in body), "")
        if not matched:
            return None
        return self.build_finding(
            title="Subdomain takeover possible",
            severity=Severity.HIGH,
            url=f"https://{host}/",
            location="config",
            description=(
                f"{host} resolves through {target} ({provider}) and returns the provider's unclaimed-resource "
                f"page ('{matched}'). The name can likely be claimed by an attacker."
            ),
            impact=(
                "An attacker can host content on the organization's subdomain, enabling phishing, cookie "
                "theft and bypass of domain-based trust controls."
            ),
            confidence=Confidence.LIKELY,
            cwe=("CWE-350",),
            tags=("takeover", "dns"),
            evidence=[
                self.capture(response, summary="Unclaimed provider page", data={"cname_chain": chain, "provider": provider})
            ],
            metadata={"cname_chain": chain, "provider": provider},
        )
