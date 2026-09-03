"""CLI exit codes, text output, and --json."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "fake_tree"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ownscan", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_clean_path_exits_zero():
    result = _run(str(FIXTURES / "clean.py"))
    assert result.returncode == 0
    assert "No findings." in result.stdout


def test_dirty_tree_exits_one_and_prints_path_line_type():
    result = _run(str(FIXTURES))
    assert result.returncode == 1
    assert "aws_access_key" in result.stdout
    assert "github_pat" in result.stdout
    assert ":" in result.stdout
    # path:line: type: snippet
    sample = next(line for line in result.stdout.splitlines() if "aws_access_key" in line)
    parts = sample.split(": ", 2)
    assert len(parts) >= 2
    assert "aws.txt" in parts[0]


def test_json_flag_emits_objects():
    result = _run("--json", str(FIXTURES))
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)
    assert payload
    assert {"path", "line", "type", "snippet"} <= set(payload[0].keys())
    types = {item["type"] for item in payload}
    assert "committed_env" in types
    assert "dockerfile_user_root" in types


def test_missing_path_exits_two():
    result = _run(str(FIXTURES / "does-not-exist"))
    assert result.returncode == 2
    assert "path not found" in result.stderr
