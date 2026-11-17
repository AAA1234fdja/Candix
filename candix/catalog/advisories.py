"""Local outdated-component advisories.

Candix ships a small, conservative advisory table for components it can
fingerprint reliably (JavaScript libraries and common web servers). Entries are
expressed as version comparisons rather than CVE identifiers so the table can be
maintained without a vulnerability feed; the report tells the team to confirm
against the vendor advisory and the SBOM before acting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Advisory:
    component: str
    fixed_version: str
    severity: str
    summary: str
    cwe: tuple[str, ...] = ()
    reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "fixed_version": self.fixed_version,
            "severity": self.severity,
            "summary": self.summary,
            "cwe": list(self.cwe),
            "reference": self.reference,
        }


ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        component="jQuery",
        fixed_version="3.5.0",
        severity="medium",
        summary="Versions before 3.5.0 are affected by prototype pollution in jQuery.extend and by HTML-injection flaws in htmlPrefilter. Upgrade to 3.7.x or later.",
        cwe=("CWE-1321", "CWE-79"),
        reference="https://blog.jquery.com/2020/04/10/jquery-3-5-0-released-important-security-updates/",
    ),
    Advisory(
        component="jQuery",
        fixed_version="1.9.0",
        severity="high",
        summary="Legacy jQuery releases before 1.9 contain multiple DOM XSS issues and are end-of-life. Migrate to a supported release.",
        cwe=("CWE-79",),
        reference="https://jquery.com/upgrade-guide/1.9/",
    ),
    Advisory(
        component="Bootstrap",
        fixed_version="3.4.1",
        severity="medium",
        summary="Bootstrap before 3.4.1 is affected by cross-site scripting in the tooltip and popover data attributes.",
        cwe=("CWE-79",),
        reference="https://blog.getbootstrap.com/2019/02/13/bootstrap-4-3-1-and-3-4-1/",
    ),
    Advisory(
        component="Angular",
        fixed_version="1.8.0",
        severity="medium",
        summary="AngularJS is end-of-life. Versions before 1.8 received security fixes only through extended support; migrate to a supported framework.",
        cwe=("CWE-1104",),
        reference="https://docs.angularjs.org/misc/version-support-status",
    ),
    Advisory(
        component="nginx",
        fixed_version="1.24.0",
        severity="low",
        summary="Older nginx branches are out of support and accumulate HTTP parsing fixes. Track the stable branch and subscribe to nginx security advisories.",
        cwe=("CWE-1104",),
        reference="https://nginx.org/en/security_advisories.html",
    ),
    Advisory(
        component="Apache HTTP Server",
        fixed_version="2.4.58",
        severity="medium",
        summary="Apache 2.4 releases before 2.4.58 include fixes for request smuggling and mod_proxy issues. Review the vendor changelog.",
        cwe=("CWE-444",),
        reference="https://httpd.apache.org/security/vulnerabilities_24.html",
    ),
    Advisory(
        component="PHP",
        fixed_version="8.1.0",
        severity="medium",
        summary="The deployed PHP branch is end-of-life. Unsupported branches no longer receive security fixes.",
        cwe=("CWE-1104",),
        reference="https://www.php.net/supported-versions.php",
    ),
    Advisory(
        component="Express",
        fixed_version="4.19.2",
        severity="low",
        summary="Older Express releases have open-redirect and response-splitting fixes in their dependencies. Upgrade and run npm audit.",
        cwe=("CWE-601",),
        reference="https://expressjs.com/en/changelog/",
    ),
    Advisory(
        component="Django",
        fixed_version="4.2.0",
        severity="medium",
        summary="The deployed Django release is outside its security support window. Upgrade to a supported LTS branch.",
        cwe=("CWE-1104",),
        reference="https://www.djangoproject.com/download/",
    ),
    Advisory(
        component="Spring Boot",
        fixed_version="3.2.0",
        severity="medium",
        summary="Older Spring Boot lines are out of open-source support. Upgrade to a supported line and review actuator exposure.",
        cwe=("CWE-1104",),
        reference="https://spring.io/projects/spring-boot#support",
    ),
)


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value)[:4])


def is_outdated(version: str, fixed: str) -> bool:
    if not version:
        return False
    current = _version_tuple(version)
    target = _version_tuple(fixed)
    if not current or not target:
        return False
    length = max(len(current), len(target))
    current += (0,) * (length - len(current))
    target += (0,) * (length - len(target))
    return current < target


def advisories_for(component: str, version: str) -> list[Advisory]:
    results: list[Advisory] = []
    for advisory in ADVISORIES:
        if advisory.component.lower() != component.lower():
            continue
        if version and is_outdated(version, advisory.fixed_version):
            results.append(advisory)
    return results


def advisory_index() -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for advisory in ADVISORIES:
        index.setdefault(advisory.component, []).append(advisory.to_dict())
    return index
