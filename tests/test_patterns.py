"""Unit tests for detection regexes and helpers."""

from ownscan.patterns import (
    AWS_ACCESS_KEY,
    CORS_WILDCARD,
    DEBUG_TRUE,
    GITHUB_PAT,
    PEM_HEADER,
    SLACK_TOKEN,
    env_assignment_value,
    is_config_file,
    is_dockerfile,
    is_env_file,
)
from pathlib import Path

AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"
GHP = "ghp_EXAMPLEFAKESECRETTOKEN00000000000000"


def test_aws_access_key_and_akia_style():
    assert AWS_ACCESS_KEY.search(f"id={AWS_EXAMPLE}")
    assert not AWS_ACCESS_KEY.search("AKIA_SHORT")
    assert not AWS_ACCESS_KEY.search("akiaiosfodnn7example")


def test_github_pats():
    assert GITHUB_PAT.search(GHP)
    assert GITHUB_PAT.search("github_pat_EXAMPLE_FAKE_00000000000000000000")
    assert not GITHUB_PAT.search("ghp_tooshort")


def test_slack_token():
    assert SLACK_TOKEN.search("xoxb-EXAMPLEFAKETOKENVALUE")
    assert not SLACK_TOKEN.search("xoxb-short")


def test_pem_header():
    assert PEM_HEADER.search("-----BEGIN RSA PRIVATE KEY-----")
    assert PEM_HEADER.search("-----BEGIN PRIVATE KEY-----")
    assert PEM_HEADER.search("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert not PEM_HEADER.search("-----BEGIN CERTIFICATE-----")


def test_env_assignment_requires_nonempty_secretish_name():
    assert env_assignment_value("API_KEY=EXAMPLEFAKEKEY") == "EXAMPLEFAKEKEY"
    assert env_assignment_value("export SECRET_KEY=EXAMPLE_FAKE_NOT_A_REAL_SECRET")
    assert env_assignment_value('PASSWORD="example_fake_password"') == "example_fake_password"
    assert env_assignment_value("MY_TOKEN=abc123") == "abc123"
    assert env_assignment_value("API_KEY=") is None
    assert env_assignment_value("API_KEY=  ") is None
    assert env_assignment_value("UNRELATED=hello") is None
    assert env_assignment_value("# TOKEN=nope") is None
    assert env_assignment_value("EMPTY_SECRET=") is None


def test_debug_true():
    assert DEBUG_TRUE.search("DEBUG = True")
    assert DEBUG_TRUE.search("debug: true")
    assert not DEBUG_TRUE.search("debug: false")


def test_cors_wildcard():
    assert CORS_WILDCARD.search("add_header Access-Control-Allow-Origin *;")
    assert CORS_WILDCARD.search("Access-Control-Allow-Origin: *")
    assert CORS_WILDCARD.search('"Access-Control-Allow-Origin": "*"')
    assert not CORS_WILDCARD.search("Access-Control-Allow-Origin: https://example.com")


def test_filename_helpers():
    assert is_env_file(Path("/repo/.env"))
    assert is_env_file(Path("/repo/.env.local"))
    assert not is_env_file(Path("/repo/.env.example"))
    assert is_dockerfile(Path("/repo/Dockerfile"))
    assert is_dockerfile(Path("/repo/deploy/Dockerfile"))
    assert is_config_file(Path("/repo/app/config.py"))
    assert is_config_file(Path("/repo/app/application.yml"))
    assert not is_config_file(Path("/repo/clean.py"))
