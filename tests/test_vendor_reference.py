import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "artex-reference"
EXPECTED = {
    "agent/budget.go",
    "agent/data_envelope.go",
    "agent/noise_profile.go",
    "agent/planner.go",
    "agent/toolcatalog.go",
    "agent/untrusted_prompt.go",
    "agent/worker.go",
    "egress/egress.go",
    "egress/pace.go",
    "evidence/store.go",
    "guard/guard.go",
    "intercept/alwaysallow_denylist.go",
    "intercept/argv.go",
    "intercept/risk.go",
    "intercept/target.go",
    "intercept/target_dial.go",
}


def test_reference_tree_has_the_selected_files():
    present = {str(path.relative_to(VENDOR)) for path in VENDOR.rglob("*.go")}
    assert present == EXPECTED


def test_reference_tree_carries_the_agpl_text():
    text = (VENDOR / "LICENSE").read_text(encoding="utf-8")
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in text
    assert "Version 3" in text


def test_notice_lists_every_file_and_the_commit():
    notice = (VENDOR / "NOTICE.md").read_text(encoding="utf-8")
    assert "6337341602be6aa5860b1e83138f03bdd0b78f71" in notice
    assert "AGPL" in notice
    for name in sorted(EXPECTED):
        assert f"`{name}`" in notice, name


def test_go_files_keep_their_package_header():
    for path in VENDOR.rglob("*.go"):
        head = path.read_text(encoding="utf-8").splitlines()[:15]
        assert any(line.startswith("package ") for line in head), path


def test_candix_never_imports_the_reference_tree():
    offenders = []
    for path in (ROOT / "candix").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"^\s*(?:from|import)\s+vendor\b", text, re.MULTILINE):
            offenders.append(str(path))
    assert offenders == []


def test_reference_tree_is_not_part_of_the_package():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'include = ["candix*"]' in pyproject or "packages" in pyproject
    assert not (ROOT / "candix" / "vendor").exists()
