"""OpenAPI 3.1 description of the Candix HTTP API."""

from __future__ import annotations

import json
from typing import Any

from candix import VERSION

SEVERITY = ["critical", "high", "medium", "low", "info"]


def spec(*, server_url: str = "http://127.0.0.1:8088") -> dict[str, Any]:
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Candix API",
            "version": VERSION,
            "description": (
                "Queue security assessments, follow their progress and download reports. "
                "Every scan requires an authorization document or an explicit operator declaration."
            ),
            "license": {"name": "Internal use"},
        },
        "servers": [{"url": server_url, "description": "local"}],
        "security": [{"bearer": []}],
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "opaque"},
            },
            "schemas": {
                "ScanRequest": {
                    "type": "object",
                    "required": ["targets"],
                    "properties": {
                        "targets": {"type": "array", "items": {"type": "string", "format": "uri"}, "minItems": 1},
                        "profile": {"type": "string", "enum": ["safe", "standard", "lab", "deep", "ctf"], "default": "standard"},
                        "exploit": {"type": "boolean", "default": False},
                        "engagement": {"type": "string", "description": "path to an authorization document"},
                        "authorized": {"type": "string", "description": "operator name for a temporary authorization"},
                        "formats": {"type": "array", "items": {"type": "string", "enum": ["json", "html", "markdown", "sarif", "csv"]}},
                        "max_rps": {"type": "number", "minimum": 0.1, "maximum": 200},
                        "max_pages": {"type": "integer", "minimum": 1},
                        "detectors": {"type": "array", "items": {"type": "string"}},
                        "categories": {"type": "array", "items": {"type": "string"}},
                        "min_severity": {"type": "string", "enum": SEVERITY, "default": "info"},
                        "max_proofs": {"type": "integer", "minimum": 0},
                        "title": {"type": "string"},
                    },
                },
                "Job": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "state": {"type": "string", "enum": ["queued", "running", "succeeded", "failed", "cancelled"]},
                        "phase": {"type": "string"},
                        "progress": {"type": "number"},
                        "counts": {"type": "object", "additionalProperties": {"type": "integer"}},
                        "risk_score": {"type": "number"},
                        "artifacts": {"type": "object", "additionalProperties": {"type": "string"}},
                        "error": {"type": "string"},
                    },
                },
                "Error": {
                    "type": "object",
                    "properties": {"error": {"type": "string"}, "details": {"type": "object"}},
                },
            },
            "responses": {
                "Error": {
                    "description": "request failed",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                }
            },
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "Liveness probe",
                    "security": [],
                    "responses": {"200": {"description": "service is running"}},
                }
            },
            "/version": {
                "get": {
                    "summary": "Build information",
                    "security": [],
                    "responses": {"200": {"description": "version payload"}},
                }
            },
            "/detectors": {
                "get": {
                    "summary": "Detector catalogue",
                    "responses": {"200": {"description": "detector list"}, "401": {"$ref": "#/components/responses/Error"}},
                }
            },
            "/scans": {
                "get": {
                    "summary": "List recent scans",
                    "parameters": [
                        {"name": "state", "in": "query", "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                    ],
                    "responses": {"200": {"description": "jobs"}},
                },
                "post": {
                    "summary": "Queue a scan",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ScanRequest"}}},
                    },
                    "responses": {
                        "202": {"description": "job queued"},
                        "400": {"$ref": "#/components/responses/Error"},
                        "401": {"$ref": "#/components/responses/Error"},
                        "403": {"$ref": "#/components/responses/Error"},
                    },
                },
            },
            "/scans/{id}": {
                "get": {
                    "summary": "Job status",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                        {"name": "wait", "in": "query", "schema": {"type": "number", "default": 0}},
                    ],
                    "responses": {
                        "200": {"description": "job", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Job"}}}},
                        "404": {"$ref": "#/components/responses/Error"},
                    },
                }
            },
            "/scans/{id}/report": {
                "get": {
                    "summary": "Download a report",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                        {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["json", "html", "markdown", "sarif", "csv"]}},
                        {"name": "inline", "in": "query", "schema": {"type": "boolean", "default": True}},
                    ],
                    "responses": {
                        "200": {"description": "report body"},
                        "404": {"$ref": "#/components/responses/Error"},
                        "409": {"$ref": "#/components/responses/Error"},
                    },
                }
            },
            "/scans/{id}/cancel": {
                "post": {
                    "summary": "Request cancellation",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"202": {"description": "cancellation accepted"}},
                }
            },
            "/jobs/{id}/events": {
                "get": {
                    "summary": "Progress events",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "event list"}},
                }
            },
        },
    }


def render(*, server_url: str = "http://127.0.0.1:8088", indent: int = 2) -> str:
    return json.dumps(spec(server_url=server_url), indent=indent, sort_keys=True)


def operations() -> list[dict[str, str]]:
    document = spec()
    result: list[dict[str, str]] = []
    for path, methods in document["paths"].items():
        for method, operation in methods.items():
            result.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "summary": operation.get("summary", ""),
                    "authenticated": "401" in operation.get("responses", {}),
                }
            )
    return result


def validate() -> list[str]:
    document = spec()
    problems: list[str] = []
    if not document.get("openapi", "").startswith("3."):
        problems.append("openapi version must be 3.x")
    for path, methods in document.get("paths", {}).items():
        if not path.startswith("/"):
            problems.append(f"path {path} must start with /")
        for method in methods:
            if method not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                problems.append(f"{path}: unsupported method {method}")
    return problems
