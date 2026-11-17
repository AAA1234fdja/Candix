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
    assert 'exclude = ["engine*", "docs*", "skills*", "tests*"]' in pyproject
    assert not (ROOT / "candix" / "engine").exists()


def test_no_file_or_path_carries_the_upstream_name():
    """Renaming is a maintenance promise: nothing may reintroduce the old name."""

    needle = ("art" + "ex").encode()
    named = [str(path.relative_to(ROOT)) for path in walk() if needle in str(path).lower().encode()]
    assert named == []
    offenders = []
    for path in walk():
        if not path.is_file() or path.is_symlink():
            continue
        try:
            if needle in path.read_bytes().lower():
                offenders.append(str(path.relative_to(ROOT)))
        except OSError:  # unreadable is not a rename problem
            continue
    assert offenders == []


def test_the_old_vendor_directory_is_gone():
    assert not (ROOT / "vendor").exists()
    stale = ("docs/vendor-" + "art" + "ex.md", "tests/test_vendor_" + "reference.py")
    for name in stale:
        assert not (ROOT / name).exists(), name
