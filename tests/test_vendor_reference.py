import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "artex-reference"

CURATED = (
    "guard/guard.go",
    "intercept/risk.go",
    "intercept/argv.go",
    "intercept/alwaysallow_denylist.go",
    "intercept/target.go",
    "intercept/target_dial.go",
    "egress/egress.go",
    "egress/pace.go",
    "agent/budget.go",
    "agent/noise_profile.go",
    "agent/untrusted_prompt.go",
    "agent/data_envelope.go",
    "agent/planner.go",
    "agent/worker.go",
    "agent/toolcatalog.go",
    "evidence/store.go",
)


def manifest():
    return json.loads((VENDOR / "MANIFEST.json").read_text(encoding="utf-8"))


def test_manifest_records_a_superset_of_sixty_percent():
    data = manifest()
    assert data["copied_files"] == len(data["files"])
    ratio = data["copied_files"] / data["upstream_tracked_files"]
    assert ratio >= 0.60, ratio
    assert data["coverage_percent"] >= 60.0
    assert data["commit"] == "6337341602be6aa5860b1e83138f03bdd0b78f71"


def test_every_manifest_entry_exists_with_the_recorded_hash():
    data = manifest()
    mismatches = []
    for item in data["files"]:
        path = VENDOR / item["path"]
        if not path.is_file():
            mismatches.append(f"missing: {item['path']}")
            continue
        if path.stat().st_size != item["bytes"]:
            mismatches.append(f"size: {item['path']}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            mismatches.append(f"hash: {item['path']}")
    assert mismatches == []


def test_tree_matches_the_manifest_exactly():
    data = manifest()
    listed = {item["path"] for item in data["files"]}
    metadata = {"NOTICE.md", "MANIFEST.json"}  # the only files Candix adds
    on_disk = {str(path.relative_to(VENDOR)) for path in VENDOR.rglob("*") if path.is_file()}
    assert on_disk - listed == metadata
    assert listed <= on_disk


def test_curated_high_risk_files_are_present():
    for name in CURATED:
        assert (VENDOR / name).is_file(), name


def test_binary_assets_were_skipped_deliberately():
    data = manifest()
    assert data["skipped_binary_files"] == len(data["skipped"])
    for name in data["skipped"]:
        assert Path(name).suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz"}
        assert not (VENDOR / name).exists()


def test_reference_tree_carries_the_agpl_text():
    text = (VENDOR / "LICENSE").read_text(encoding="utf-8")
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in text
    assert "Version 3" in text


def test_notice_documents_provenance_and_boundary():
    notice = (VENDOR / "NOTICE.md").read_text(encoding="utf-8")
    assert "6337341602be6aa5860b1e83138f03bdd0b78f71" in notice
    assert "AGPL" in notice and "MIT" in notice
    assert "MANIFEST.json" in notice
    for name in CURATED:
        assert f"`{name}`" in notice, name


def test_go_files_keep_their_package_clause():
    checked = 0
    for path in VENDOR.rglob("*.go"):
        head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:20]
        assert any(line.startswith("package ") for line in head), path
        checked += 1
    assert checked >= 500


def test_candix_never_imports_the_reference_tree():
    offenders = []
    for path in (ROOT / "candix").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"^\s*(?:from|import)\s+vendor\b", text, re.MULTILINE):
            offenders.append(str(path))
    assert offenders == []


def test_reference_tree_is_not_part_of_the_package():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'exclude = ["vendor*", "tests*"]' in pyproject
    assert not (ROOT / "candix" / "vendor").exists()
