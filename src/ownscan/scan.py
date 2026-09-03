"""Walk a local path and collect secret / misconfiguration findings."""

from __future__ import annotations

import os
from pathlib import Path

from ownscan.patterns import (
    AWS_ACCESS_KEY,
    CORS_WILDCARD,
    DEBUG_TRUE,
    GITHUB_PAT,
    MAX_FILE_BYTES,
    PEM_HEADER,
    SKIP_DIRS,
    SLACK_TOKEN,
    dockerfile_user,
    env_assignment_value,
    is_config_file,
    is_dockerfile,
    is_env_file,
)
from ownscan.report import Finding, snippet_for


def scan_path(root: Path | str) -> list[Finding]:
    """Scan a file or directory. Never follows symlinks and never leaves `root`."""
    root_path = Path(root).expanduser()
    if not root_path.exists():
        raise FileNotFoundError(str(root_path))
    if root_path.is_file():
        display_root = root_path.parent
        return _scan_file(root_path, display_root)

    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS)
        for name in sorted(filenames):
            filepath = Path(dirpath) / name
            if filepath.is_symlink():
                continue
            findings.extend(_scan_file(filepath, root_path))
    findings.sort(key=lambda item: (item.path, item.line, item.type))
    return findings


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _read_text(path: Path) -> str | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    if stat.st_size > MAX_FILE_BYTES:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    for encoding in ("utf-8", "utf-8-sig"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def _scan_file(path: Path, display_root: Path) -> list[Finding]:
    text = _read_text(path)
    if text is None:
        return []

    rel = _rel(path, display_root)
    findings: list[Finding] = []

    if is_env_file(path):
        findings.append(
            Finding(
                path=rel,
                line=1,
                type="committed_env",
                snippet=f"committed environment file ({path.name})",
            )
        )

    if is_dockerfile(path):
        findings.extend(_scan_dockerfile(text, rel))

    for lineno, line in enumerate(text.splitlines(), 1):
        findings.extend(_scan_line(line, lineno, rel, path))
    return findings


def _scan_dockerfile(text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    has_user = False
    for lineno, line in enumerate(text.splitlines(), 1):
        user = dockerfile_user(line)
        if user is None:
            continue
        has_user = True
        user_name = user.split(":", 1)[0]
        if user_name.lower() in {"root", "0"}:
            findings.append(
                Finding(
                    path=rel,
                    line=lineno,
                    type="dockerfile_user_root",
                    snippet=line.strip(),
                )
            )
    if not has_user:
        findings.append(
            Finding(
                path=rel,
                line=1,
                type="dockerfile_missing_user",
                snippet="Dockerfile has no USER instruction",
            )
        )
    return findings


def _scan_line(line: str, lineno: int, rel: str, path: Path) -> list[Finding]:
    findings: list[Finding] = []

    def add(kind: str, match: str) -> None:
        findings.append(
            Finding(
                path=rel,
                line=lineno,
                type=kind,
                snippet=snippet_for(kind, line, match),
            )
        )

    for match in AWS_ACCESS_KEY.finditer(line):
        add("aws_access_key", match.group(0))
    for match in GITHUB_PAT.finditer(line):
        add("github_pat", match.group(0))
    for match in SLACK_TOKEN.finditer(line):
        add("slack_token", match.group(0))
    for match in PEM_HEADER.finditer(line):
        add("pem_private_key", match.group(0))

    env_value = env_assignment_value(line)
    if env_value is not None:
        add("env_secret", env_value)

    if is_config_file(path):
        debug = DEBUG_TRUE.search(line)
        if debug:
            add("debug_enabled", debug.group(0))

    cors = CORS_WILDCARD.search(line)
    if cors:
        add("cors_wildcard", cors.group(0))

    return findings
