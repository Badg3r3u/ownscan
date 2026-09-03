# ownscan

A small, local-only CLI that looks for **accidentally committed secrets** and a handful of **common configuration smells** in a directory you already own.

ownscan is a defensive hygiene tool. It reads files on disk, prints findings, and exits. It does not connect to the network, does not scan remote hosts, and does not attempt to use or validate any credential it finds.

## Why

Source trees pick up leftovers: an `.env` copied into git, a debug flag left on, a Dockerfile that still runs as root, a sample key that was a little too realistic. Catching those in your own checkout is cheaper than catching them after a push.

ownscan is intentionally narrow. It is not a substitute for a full SAST platform, a cloud posture scanner, or a secret-rotation process.

## What it looks for

**Secrets (values are redacted in output)**

- AWS access key IDs and generic `AKIA…` identifiers
- GitHub personal access tokens (`ghp_…`, `github_pat_…`)
- Slack bot/user tokens (`xoxb-` / `xoxp-` / similar)
- PEM / OpenSSH private-key armor headers
- `.env`-style assignments whose names look like `SECRET`, `PASSWORD`, `API_KEY`, or `TOKEN` and whose values are non-empty

**Configuration smells**

- `debug = true` / `DEBUG = True` in common config files
- `Access-Control-Allow-Origin` set to `*`
- Committed dotenv files (`.env`, `.env.local`, … — templates like `.env.example` are skipped)
- Dockerfiles that use `USER root`, or that have no `USER` instruction at all

**Directories skipped**

`.git`, `node_modules`, `venv`, `.venv`, `dist`, `__pycache__`, `.tox`, `site-packages`

## Install

Python 3.11 or newer.

```bash
pip install -e .
```

For tests:

```bash
pip install -e ".[dev]"
```

## Run

Scan a project directory:

```bash
ownscan PATH
```

JSON instead of text:

```bash
ownscan --json PATH
```

Exit codes:

| Code | Meaning              |
|------|----------------------|
| 0    | No findings          |
| 1    | One or more findings |
| 2    | Path does not exist  |

`python -m ownscan PATH` works the same way.

## Sample output

Against the bundled **FAKE/EXAMPLE** fixture tree (placeholders only, never real credentials):

```text
$ ownscan fixtures/fake_tree
.env:1: committed_env: committed environment file (.env)
.env:2: env_secret: SECRET_KEY=EXAM…CRET
Dockerfile:3: dockerfile_user_root: USER root
app/config.py:3: debug_enabled: DEBUG = True
app/cors.conf:2: cors_wildcard: add_header Access-Control-Allow-Origin *;
aws.txt:2: aws_access_key: aws_access_key_id = AKIA…MPLE
deploy/Dockerfile:1: dockerfile_missing_user: Dockerfile has no USER instruction
github.txt:2: github_pat: classic = ghp_…0000
keys/id_rsa.example:2: pem_private_key: -----BEGIN RSA PRIVATE KEY-----
slack.txt:2: slack_token: SLACK_BOT_TOKEN=xoxb…0000
```

Exact line numbers and redaction widths may differ slightly; the shape is `path:line: type: snippet`.

`--json` emits a list of objects with `path`, `line`, `type`, and `snippet`.

## Limitations

- **Local files only.** There is no remote scan, no git-history crawl, and no cloud API check.
- **Pattern-based.** High-entropy blobs that do not match a known shape are not reported. Known shapes in comments or docs can still match.
- **Not a verifier.** A hit means “this looks like a leak or a smell,” not “this credential is live.”
- **Redaction is best-effort.** Treat reports as sensitive if the original tree was.
- **Not an exploit toolkit and not a pentest lab.** It will not generate payloads, attack services, or use discovered credentials.

If ownscan reports a real secret in a repository you maintain, rotate that credential and remove it from history — don’t just delete the line on `main`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Fixture secrets under `fixtures/fake_tree/` are labeled **FAKE/EXAMPLE** and include well-known documentation placeholders (for example AWS’s public example access key ID). They are not usable credentials.

## License

MIT. See [LICENSE](LICENSE).
