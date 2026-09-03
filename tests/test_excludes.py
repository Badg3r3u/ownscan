"""Skipped directories must never contribute findings."""

from pathlib import Path

from ownscan.scan import scan_path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "fake_tree"

SKIPPED = (
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    ".git",
    ".tox",
    "site-packages",
)


def test_skipped_directory_names_never_appear_in_paths():
    findings = scan_path(FIXTURES)
    for item in findings:
        parts = set(item.path.replace("\\", "/").split("/"))
        leaked = parts.intersection(SKIPPED)
        assert not leaked, f"{item.path} leaked skipped dir {leaked}"


def test_secrets_inside_node_modules_are_ignored():
    findings = scan_path(FIXTURES)
    assert not any("node_modules" in f.path for f in findings)
    nested = FIXTURES / "node_modules" / "evil" / "secret.js"
    assert nested.is_file()  # fixture exists; skip is the behavior under test


def test_secrets_inside_venv_and_pycache_are_ignored():
    findings = scan_path(FIXTURES)
    joined = " ".join(f.path for f in findings)
    assert "venv/" not in joined
    assert "__pycache__" not in joined
