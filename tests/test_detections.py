"""Integration tests against fixtures/fake_tree (all values are FAKE/EXAMPLE)."""

from pathlib import Path

from ownscan.report import redact_secret
from ownscan.scan import scan_path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "fake_tree"

AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"
GHP = "ghp_EXAMPLEFAKESECRETTOKEN00000000000000"


def _posix(path: str) -> str:
    return path.replace("\\", "/")


def test_scan_reports_each_required_type():
    findings = scan_path(FIXTURES)
    types = {item.type for item in findings}
    expected = {
        "aws_access_key",
        "github_pat",
        "slack_token",
        "pem_private_key",
        "env_secret",
        "debug_enabled",
        "cors_wildcard",
        "committed_env",
        "dockerfile_user_root",
        "dockerfile_missing_user",
    }
    missing = expected - types
    assert not missing, f"missing types: {missing}; got {sorted(types)}"


def test_aws_finding_points_at_aws_fixture():
    findings = [f for f in scan_path(FIXTURES) if f.type == "aws_access_key"]
    assert any("aws.txt" in _posix(f.path) for f in findings)


def test_github_classic_and_fine_grained():
    findings = [f for f in scan_path(FIXTURES) if f.type == "github_pat"]
    assert any("github.txt" in _posix(f.path) for f in findings)
    assert len(findings) >= 2


def test_committed_env_flags_dotenv_file():
    findings = [f for f in scan_path(FIXTURES) if f.type == "committed_env"]
    assert any(_posix(f.path).endswith(".env") for f in findings)
    assert all(".env.example" not in _posix(f.path) for f in findings)


def test_env_secret_lines_detected_and_empties_ignored():
    env_findings = [
        f
        for f in scan_path(FIXTURES)
        if f.type == "env_secret" and _posix(f.path).endswith(".env")
    ]
    kinds_present = " ".join(f.snippet for f in env_findings)
    assert env_findings
    # Redacted snippets still mention the variable side of the assignment.
    assert any("SECRET_KEY" in f.snippet or "API_KEY" in f.snippet or "PASSWORD" in f.snippet or "TOKEN" in f.snippet for f in env_findings)
    assert "EMPTY_SECRET" not in kinds_present


def test_dockerfile_user_root_and_missing_user():
    findings = scan_path(FIXTURES)
    root_hits = [f for f in findings if f.type == "dockerfile_user_root"]
    missing = [f for f in findings if f.type == "dockerfile_missing_user"]
    assert any(_posix(f.path) == "Dockerfile" for f in root_hits)
    assert any("deploy/Dockerfile" in _posix(f.path) for f in missing)


def test_debug_and_cors_in_config_files():
    findings = scan_path(FIXTURES)
    assert any(f.type == "debug_enabled" and "config.py" in _posix(f.path) for f in findings)
    assert any(f.type == "debug_enabled" and "application.yml" in _posix(f.path) for f in findings)
    assert any(f.type == "cors_wildcard" and "cors.conf" in _posix(f.path) for f in findings)


def test_clean_file_has_no_findings():
    assert scan_path(FIXTURES / "clean.py") == []


def test_snippets_never_contain_full_aws_or_github_examples():
    findings = scan_path(FIXTURES)
    blob = "\n".join(f.snippet for f in findings)
    assert AWS_EXAMPLE not in blob
    assert GHP not in blob


def test_redact_secret_masks_middle():
    masked = redact_secret(AWS_EXAMPLE)
    assert AWS_EXAMPLE not in masked
    assert masked.startswith("AKIA")
