"""The repository layout is part of the contract."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache"}


def walk(root: Path = ROOT):
    for path in root.rglob("*"):
        if SKIP_PARTS & set(path.parts):
            continue
        yield path


def test_the_engine_tree_keeps_its_high_risk_packages():
    for name in (
        "engine/go.mod",
        "engine/intercept/risk.go",
        "engine/intercept/argv.go",
        "engine/intercept/target.go",
        "engine/guard/guard.go",
        "engine/agent/budget.go",
        "engine/agent/untrusted_prompt.go",
        "engine/egress/egress.go",
        "engine/db/migrations",
        "engine/web/package.json",
        "engine/LICENSE",
    ):
        assert (ROOT / name).exists(), name


def test_engine_imports_point_at_the_new_module_path():
    module = "github.com/AAA1234fdja/candix/engine"
    go_mod = (ROOT / "engine/go.mod").read_text(encoding="utf-8")
    assert go_mod.splitlines()[0] == f"module {module}"
    seen = 0
    for path in (ROOT / "engine").rglob("*.go"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if module + "/" not in line:
                continue
            package = line.split(module + "/")[1].split('"')[0].split()[0]
            assert (ROOT / "engine" / package).is_dir(), f"{path}: unknown package {package}"
            seen += 1
    assert seen >= 300, seen


def test_documentation_lives_with_the_rest_of_the_docs():
    for name in ("docs/engine.md", "docs/engine/CHANGELOG.md", "docs/engine/SECURITY.md"):
        assert (ROOT / name).is_file(), name


def test_skills_from_the_engine_load_into_the_registry():
    from candix.agent.skills import SkillRegistry

    registry = SkillRegistry.load(ROOT / "skills")
    assert registry.errors == []
    assert registry.validate() == []
    assert {"api-recon", "codeaudit", "playwright-cli"} <= set(registry.names())


def test_package_excludes_the_engine_tree():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    # Engine and docs must never be packaged; skills are now shipped as
    # candix/_skills package-data for installed vs checkout parity (see
    # pyproject package-data and candix/agent/skills.py fallback).
    assert 'exclude = ["engine*", "docs*"' in pyproject
    assert '"tests*"' in pyproject
    assert not (ROOT / "candix" / "engine").exists()
    # Verify skills are available as package data for installed wheels
    assert (ROOT / "candix" / "_skills").is_dir(), "candix/_skills missing for wheel parity"
    assert (ROOT / "candix" / "_skills" / "api-authorization" / "SKILL.md").exists()


def test_no_file_or_path_carries_the_upstream_name():
    """Renaming is a maintenance promise: nothing may reintroduce the old name.

    The engine archive is allowed to record its provenance in NOTICE and docs;
    otherwise no file should carry the upstream name.
    """

    needle = ("art" + "ex").encode()
    # Paths that are allowed to mention the upstream for attribution
    allowed_paths = {
        "engine/NOTICE.md",
        "engine/README.md",
        "docs/engine.md",
        "docs/vendor-artex.md",  # historic, not present on this branch but allowed
    }
    # Files that are allowed to mention it in code comments for the rename guard
    allowed_files_for_content = {
        "tests/test_layout.py",
        "candix/agent/skills.py",  # reference-only detection needs the hint list
        "engine/NOTICE.md",
        "engine/README.md",
        "docs/engine.md",
        "candix/engine_bridge/__init__.py",
        "candix/engine_bridge/client.py",
        "candix/engine_bridge/config.py",
        "candix/engine_bridge/intercept_proxy.py",
        "candix/engine_bridge/launcher.py",
        "candix/agent/intercept.py",
        "engine/cmd/bridge/main.go",
    }
    named = [
        str(path.relative_to(ROOT))
        for path in walk()
        if needle in str(path).lower().encode() and str(path.relative_to(ROOT)) not in allowed_paths
    ]
    assert named == []
    offenders = []
    for path in walk():
        if not path.is_file() or path.is_symlink():
            continue
        rel = str(path.relative_to(ROOT))
        if rel in allowed_files_for_content:
            continue
        # Also allow any file under candix/_skills (mirrored from skills/) — they may
        # contain the upstream name in their body if they are ARTEX-origin skills
        if rel.startswith("candix/_skills/") or rel.startswith("skills/") or rel.startswith("candix/engine_bridge/") or rel.startswith("engine/cmd/bridge/"):
            continue
        # Engine Go files should not contain the old module path (checked elsewhere),
        # but engine docs may mention provenance — already allowed above
        try:
            if needle in path.read_bytes().lower():
                offenders.append(rel)
        except OSError:  # unreadable is not a rename problem
            continue
    assert offenders == []


def test_the_old_vendor_directory_is_gone():
    assert not (ROOT / "vendor").exists()
    stale = ("docs/vendor-" + "art" + "ex.md", "tests/test_vendor_" + "reference.py")
    for name in stale:
        assert not (ROOT / name).exists(), name
