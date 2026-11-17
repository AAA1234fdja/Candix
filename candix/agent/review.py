"""Peer review before a finding reaches the client."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from candix.agent.knowledge import guidance_for, verify_plan

STATUSES = ("pending", "in_review", "changes", "approved", "rejected")
DEFAULT_ITEMS = (
    "the finding is reproducible from the attached exchange alone",
    "severity matches the demonstrated impact, not the title",
    "no client data beyond the minimum is included",
    "remediation names the control that failed",
)


@dataclass
class Item:
    text: str
    checked: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "checked": self.checked, "note": self.note}


@dataclass
class Review:
    finding_key: str
    title: str
    status: str = "pending"
    reviewer: str = ""
    items: list[Item] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    updated_at: float = field(default_factory=time.time)

    @classmethod
    def forget(cls, finding: dict[str, Any]) -> "Review":
        key = str(finding.get("id") or f"{finding.get('title', '')}|{finding.get('url', '')}")
        review = cls(finding_key=key, title=str(finding.get("title", "")))
        for text in DEFAULT_ITEMS:
            review.items.append(Item(text=text))
        for step in verify_plan(finding)[:3]:
            review.items.append(Item(text=f"verification step: {step}"))
        return review

    @property
    def progress(self) -> float:
        if not self.items:
            return 0.0
        return round(sum(1 for item in self.items if item.checked) / len(self.items), 3)

    def check(self, index: int, *, note: str = "") -> None:
        if 0 <= index < len(self.items):
            self.items[index].checked = True
            if note:
                self.items[index].note = note
            self.touch()

    def uncheck(self, index: int) -> None:
        if 0 <= index < len(self.items):
            self.items[index].checked = False
            self.touch()

    def touch(self, *, status: str = "") -> None:
        if status:
            if status not in STATUSES:
                raise ValueError(f"unknown review status: {status}")
            self.status = status
        self.updated_at = time.time()

    def approve(self, reviewer: str) -> None:
        if self.progress < 1.0:
            raise ValueError(f"{len(self.items)} item(s) still unchecked")
        self.reviewer = reviewer
        self.status = "approved"
        self.updated_at = time.time()

    def reject(self, reviewer: str, reason: str) -> None:
        self.reviewer = reviewer
        self.status = "rejected"
        self.comments.append(reason.strip())
        self.updated_at = time.time()

    def comment(self, text: str) -> None:
        if text.strip():
            self.comments.append(text.strip())
            self.touch()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding_key,
            "title": self.title,
            "status": self.status,
            "reviewer": self.reviewer,
            "progress": self.progress,
            "items": [item.to_dict() for item in self.items],
            "comments": self.comments,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Review":
        review = cls(
            finding_key=str(payload.get("finding", "")),
            title=str(payload.get("title", "")),
            status=str(payload.get("status", "pending")),
            reviewer=str(payload.get("reviewer", "")),
            comments=list(payload.get("comments") or []),
            updated_at=float(payload.get("updated_at", time.time())),
        )
        review.items = [Item(text=str(item.get("text", "")), checked=bool(item.get("checked")), note=str(item.get("note", ""))) for item in payload.get("items") or []]
        return review

    def markdown(self) -> str:
        lines = [f"### {self.title or self.finding_key}", "", f"- status: **{self.status}**", f"- reviewer: {self.reviewer or 'unassigned'}", f"- checklist: {self.progress:.0%}", ""]
        for item in self.items:
            mark = "x" if item.checked else " "
            suffix = f" — {item.note}" if item.note else ""
            lines.append(f"- [{mark}] {item.text}{suffix}")
        if self.comments:
            lines += ["", "Comments:", *[f"- {comment}" for comment in self.comments]]
        return "\n".join(lines) + "\n"


@dataclass
class ReviewBoard:
    reviews: dict[str, Review] = field(default_factory=dict)
    path: str = ""

    def seed(self, findings: Iterable[dict[str, Any]]) -> int:
        added = 0
        for finding in findings:
            review = Review.forget(finding)
            existing = self.reviews.get(review.finding_key)
            if existing is None:
                self.reviews[review.finding_key] = review
                added += 1
            else:
                # keep reviewer progress, add any new checklist item
                known = {item.text for item in existing.items}
                for item in review.items:
                    if item.text not in known:
                        existing.items.append(item)
        return added

    def get(self, key: str) -> Review | None:
        return self.reviews.get(key)

    def pending(self) -> list[Review]:
        return [review for review in self.reviews.values() if review.status in {"pending", "in_review", "changes"}]

    def approved(self) -> list[Review]:
        return [review for review in self.reviews.values() if review.status == "approved"]

    def blocked(self) -> list[Review]:
        return [review for review in self.reviews.values() if review.status == "rejected"]

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {status: 0 for status in STATUSES}
        for review in self.reviews.values():
            counts[review.status] = counts.get(review.status, 0) + 1
        total = len(self.reviews)
        return {
            "total": total,
            "counts": counts,
            "approved_ratio": round(len(self.approved()) / total, 3) if total else 0.0,
            "ready": not self.pending() and not self.blocked(),
        }

    def markdown(self) -> str:
        lines = ["## Finding review", ""]
        summary = self.summary()
        lines.append(f"{summary['total']} finding(s) under review · {summary['approved_ratio']:.0%} approved")
        lines.append("")
        for review in sorted(self.reviews.values(), key=lambda item: (item.status != "approved", item.title)):
            lines.append(review.markdown())
        return "\n".join(lines)

    def save(self, path: str | Path | None = None) -> str:
        target = Path(path or self.path)
        if not str(target):
            raise ValueError("no path for the review board")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "reviews": [review.to_dict() for review in self.reviews.values()]}
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str | Path) -> "ReviewBoard":
        source = Path(path)
        if not source.is_file():
            return cls(path=str(source))
        payload = json.loads(source.read_text(encoding="utf-8"))
        board = cls(path=str(source))
        for entry in payload.get("reviews") or []:
            review = Review.from_dict(entry)
            board.reviews[review.finding_key] = review
        return board

    def approve_all(self, reviewer: str) -> int:
        approved = 0
        for review in self.reviews.values():
            if review.status == "approved":
                continue
            for item in review.items:
                item.checked = True
            review.reviewer = reviewer
            review.status = "approved"
            review.updated_at = time.time()
            approved += 1
        return approved

    def assign(self, reviewer: str) -> int:
        assigned = 0
        for review in self.pending():
            if not review.reviewer:
                review.reviewer = reviewer
                review.status = "in_review"
                review.updated_at = time.time()
                assigned += 1
        return assigned


def guidelines(finding: dict[str, Any]) -> list[str]:
    item = guidance_for(finding)
    if not item:
        return list(DEFAULT_ITEMS)
    return [
        *DEFAULT_ITEMS,
        f"impact statement matches {item.cwe}",
        f"remediation covers: {item.remediation[0]}",
    ]


def block_release(board: ReviewBoard, *, require_all: bool = True) -> tuple[bool, str]:
    pending = board.pending()
    if require_all and pending:
        return False, f"{len(pending)} finding(s) still under review"
    if board.blocked():
        return False, f"{len(board.blocked())} finding(s) rejected"
    return True, "every finding is approved"
