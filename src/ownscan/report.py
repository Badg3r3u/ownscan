"""Finding model and human/JSON report rendering."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

SECRET_TYPES = frozenset(
    {
        "aws_access_key",
        "github_pat",
        "slack_token",
        "pem_private_key",
        "env_secret",
    }
)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    type: str
    snippet: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def redact_secret(value: str, keep: int = 4) -> str:
    """Mask the middle of a credential so reports are safe to paste."""
    if not value:
        return ""
    if len(value) <= keep * 2:
        return f"{value[:1]}***"
    return f"{value[:keep]}…{value[-keep:]}"


def redact_line(line: str, match: str) -> str:
    """Return a single-line snippet with `match` redacted if present."""
    stripped = line.strip()
    if match and match in stripped:
        return stripped.replace(match, redact_secret(match), 1)
    if len(stripped) > 120:
        return stripped[:120] + "…"
    return stripped


def snippet_for(kind: str, line: str, match: str) -> str:
    if kind in SECRET_TYPES:
        return redact_line(line, match)
    stripped = line.strip()
    if len(stripped) > 120:
        return stripped[:120] + "…"
    return stripped


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return ""
    return "\n".join(
        f"{item.path}:{item.line}: {item.type}: {item.snippet}" for item in findings
    )


def render_json(findings: list[Finding]) -> str:
    return json.dumps([item.to_dict() for item in findings], indent=2)
