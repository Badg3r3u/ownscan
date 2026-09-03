"""Regexes and filename helpers for local secret / config-smell detection."""

from __future__ import annotations

import re
from pathlib import Path

# --- skip rules ----------------------------------------------------------------

SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "dist",
        "__pycache__",
        ".tox",
        "site-packages",
    }
)

MAX_FILE_BYTES = 1_048_576  # 1 MiB; keeps the walk snappy and avoids huge blobs

# --- secret patterns -----------------------------------------------------------

# AWS access key IDs and generic AKIA-style identifiers (20 chars: AKIA + 16).
AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# Classic (`ghp_`) and fine-grained (`github_pat_`) GitHub personal access tokens.
GITHUB_PAT = re.compile(r"\b(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b")

# Slack bot / user / app tokens.
SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")

# PEM / OpenSSH private-key armor headers (the header line is enough to flag).
PEM_HEADER = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")

# Variable names that look like credentials on assignment lines.
_SECRET_NAME = re.compile(r"(?i)(?:SECRET|PASSWORD|API_KEY|TOKEN)")

DEBUG_TRUE = re.compile(r"(?i)\bdebug\s*[=:]\s*true\b")

# Header, nginx add_header, JSON key — any form that allows any origin.
CORS_WILDCARD = re.compile(
    r"(?i)access-control-allow-origin[\s" + '"' + r"':=,]+" + r"\*"
)

_USER_INSTRUCTION = re.compile(r"(?i)^USER\s+(\S+)")

# --- filename helpers ----------------------------------------------------------

_ENV_SKIP = frozenset({".env.example", ".env.sample", ".env.template"})

_CONFIG_NAMES = frozenset(
    {
        "settings.py",
        "config.py",
        "conf.py",
        "configuration.py",
        "config.yml",
        "config.yaml",
        "config.json",
        "config.toml",
        "config.ini",
        "config.cfg",
        "settings.yml",
        "settings.yaml",
        "settings.json",
        "settings.ini",
        "settings.toml",
        "appsettings.json",
        "application.yml",
        "application.yaml",
        "application.properties",
        "app.cfg",
        "app.ini",
        "app.toml",
        "web.config",
    }
)

_CONFIG_SUFFIXES = (".yml", ".yaml", ".ini", ".cfg", ".toml", ".properties")


def is_skipped_dir(name: str) -> bool:
    return name in SKIP_DIRS


def is_dockerfile(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    return name == "Dockerfile" or name.startswith("Dockerfile.") or lower.endswith(".dockerfile")


def is_env_file(path: Path) -> bool:
    """True for committed dotenv files; example/sample templates are ignored."""
    name = path.name
    if name in _ENV_SKIP:
        return False
    return name == ".env" or name.startswith(".env.")


def is_config_file(path: Path) -> bool:
    name = path.name.lower()
    if name in _CONFIG_NAMES:
        return True
    if name.endswith(_CONFIG_SUFFIXES) and any(
        token in name for token in ("config", "setting", "conf", "application")
    ):
        return True
    return False


def env_assignment_value(line: str) -> str | None:
    """Return the assigned value if this looks like a SECRET/PASSWORD/API_KEY/TOKEN line.

    Empty, comment-only, and missing values are ignored.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.lower().startswith("export "):
        stripped = stripped[7:].lstrip()
    if "=" not in stripped:
        return None
    key, _, value = stripped.partition("=")
    key = key.strip().strip('"').strip("'")
    value = value.strip()
    if not key or not _SECRET_NAME.search(key):
        return None
    if value.startswith("#"):
        return None
    # Drop an inline comment only when it is clearly separated.
    if " #" in value:
        value = value[: value.index(" #")].rstrip()
    if (len(value) >= 2) and (
        (value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")
    ):
        value = value[1:-1]
    if not value:
        return None
    return value


def dockerfile_user(line: str) -> str | None:
    """Return the USER argument if this instruction is a USER line, else None."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = _USER_INSTRUCTION.match(stripped)
    if not match:
        return None
    return match.group(1)
