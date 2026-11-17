"""Unrestricted file upload surface."""

from __future__ import annotations

import re
from typing import Iterable

from candix.core.finding import Finding
from candix.core.severity import Confidence, Severity
from candix.detectors.base import BaseDetector, DetectorMeta, register_detector

_UPLOAD_HINTS = ("upload", "attach", "file", "image", "avatar", "import", "media", "document")


@register_detector
class FileUploadDetector(BaseDetector):
    meta = DetectorMeta(
        id="fileupload",
        name="Unvalidated file upload",
        category="fileupload",
        description="Identifies upload endpoints and verifies whether a harmless text file with an active extension is stored.",
        severity=Severity.MEDIUM,
        cwe=("CWE-434",),
        owasp=("A04:2021 Insecure Design",),
        intrusive=True,
        tags=("upload", "files"),
        order=180,
        remediation_key="fileupload",
    )

    def run(self) -> Iterable[Finding]:
        seen: set[str] = set()
        for endpoint in self.ctx.endpoints:
            hints = endpoint.path.lower() + " " + " ".join(endpoint.tags).lower()
            if not any(hint in hints for hint in _UPLOAD_HINTS):
                continue
            key = endpoint.path.lower()
            if key in seen:
                continue
            seen.add(key)
            finding = self._test(endpoint)
            if finding is not None:
                yield self.emit(finding)

    def _test(self, endpoint) -> Finding | None:
        marker = self.marker("up")
        boundary = "----candix" + marker
        filename = f"candix-{marker}.txt"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            f"candix-upload-probe-{marker}\r\n"
            f"--{boundary}--\r\n"
        )
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        method = endpoint.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            method = "POST"
        try:
            response = self.http.request(method, endpoint.url, data=body.encode(), headers=headers, tag="upload")
        except Exception:
            return None
        if self.missing(response) or response.status >= 400:
            return None
        text = response.text.lower()
        accepted = any(
            token in text
            for token in ("uploaded", "success", "stored", filename.lower(), "created", "saved")
        ) or (response.status in {201, 202} and "file" in text)
        if not accepted:
            return None
        stored_path = ""
        match = re.search(r'"(?:url|path|location|file)"\s*:\s*"([^"]+)"', response.text)
        if match:
            stored_path = match.group(1)
        return self.build_finding(
            title="File upload accepts arbitrary content",
            severity=Severity.MEDIUM,
            url=endpoint.url,
            method=method,
            location="body",
            description=(
                "The upload endpoint accepted a multipart file without demonstrating type validation "
                f"(filename {filename!r}, content-type text/plain)."
                + (f" The server reported a stored location: {stored_path}." if stored_path else "")
            ),
            impact=(
                "If the stored file is served from the application origin with an executable extension, "
                "this becomes remote code execution or stored XSS."
            ),
            payload=filename,
            confidence=Confidence.LIKELY if stored_path else Confidence.POSSIBLE,
            cwe=("CWE-434",),
            tags=("upload",),
            evidence=[self.capture(response, summary="Upload accepted by the server")],
            metadata={"stored_path": stored_path, "filename": filename},
        )
