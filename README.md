# PyAudit — Automated Python Code Quality Reporter

One command. Six audits. One prioritized report (terminal, HTML, JSON, or a browser).

```bash
pip install -e .
pyaudit scan ./your-project
```

Prefer a browser? `pyaudit web` launches a local web UI so you can run scans and
browse reports without touching the CLI:

```bash
pyaudit web
# → http://127.0.0.1:8765
```

## Status

- [x] Package skeleton (`pyproject.toml`, installable via `pip install -e .`)
- [x] Typer CLI: `pyaudit scan <path>`, `pyaudit compare <before.json> <after.json>`
- [x] Complexity auditor (`radon`) - per-function cyclomatic complexity + risk rank,
      per-file maintainability index
- [x] Static analysis (`pylint`) - errors/warnings/conventions/refactors
- [x] Dead code detection (`vulture`) - unused functions, methods, variables
- [x] Security scanner (`bandit`) - OWASP-mapped findings by severity
- [x] Dependency audit (`pip-audit`) - CVEs against `requirements.txt`,
      `pyproject.toml` (PEP 621 or Poetry), or `Pipfile`
- [x] Coverage reporter (`coverage.py` + `pytest`) - runs the target's own test suite
- [x] Health score (weighted across all six audits)
- [x] Rich terminal output
- [x] HTML report (self-contained, dark-mode, dashboard-style with a health-score
      gauge, letter grade, section nav, and per-audit stat cards — `--output report.html`)
- [x] JSON report (`--output report.json`, for CI / `compare`)
- [x] `--ci --min-score` quality gate
- [x] `pyaudit compare` for regression detection between two JSON reports
- [x] `pyaudit web` — local Flask web UI: submit a project path from a form, view
      the same report in the browser, download it as HTML/JSON, browse a
      per-session scan history
- [x] `pyaudit scan <github-url>` — clone-and-scan a public GitHub repo directly
      from its URL, no local checkout needed
- [x] `.pyaudit.toml` — per-project config for thresholds and ignored paths,
      picked up automatically from the scanned project's root
- [x] CI integration example (`.github/workflows/ci.yml`) — runs the test suite,
      then a self-audit quality gate

## A deviation from the original spec worth knowing about

The spec named `safety` for the dependency audit. I used **`pip-audit`** instead —
`safety`'s current CLI increasingly pushes users toward a paid/login-gated flow,
which conflicts with the "no API keys, zero cost" goal. `pip-audit` is MIT-licensed,
maintained by PyPA, needs no account, and queries the same class of vulnerability
databases (OSV + PyPI advisories). Swap it back to `safety` in
`pyaudit/audit/dependencies.py` if you'd rather match the spec verbatim.

## Install (dev)

```bash
py -3 -m venv .venv
.venv\Scripts\Activate.ps1      # Windows PowerShell
pip install -e .
```

Requires Python 3.10+ (the codebase uses `X | Y` union type hints throughout).
Installs all six audit tools (`radon`, `pylint`, `vulture`, `bandit`, `pip-audit`,
`coverage`) plus `pytest`, `typer`, `rich`, `jinja2`, `flask` as real dependencies —
nothing extra to install by hand.

## Usage

```bash
# Terminal output only
pyaudit scan ./your-project

# Scan a public GitHub repo directly — no local clone needed
pyaudit scan https://github.com/psf/requests

# Tune thresholds
pyaudit scan ./your-project --complexity-threshold 8 --coverage-target 90

# Reports
pyaudit scan ./your-project --output report.html
pyaudit scan ./your-project --output report.json

# Skip the test-suite-driven coverage audit (fastest, and the one audit that
# depends on the target project's own dependencies being importable here)
pyaudit scan ./your-project --skip-coverage

# CI quality gate — exits 1 if health score < 70
pyaudit scan . --ci --min-score 70

# Compare two JSON reports and fail if anything regressed
pyaudit scan . --output before.json     # run on main
pyaudit scan . --output after.json      # run on your branch
pyaudit compare before.json after.json

# Web UI — run scans and browse reports from a browser instead of the CLI
pyaudit web                             # http://127.0.0.1:8765
pyaudit web --port 9000
```

### Per-project config: `.pyaudit.toml`

Drop a `.pyaudit.toml` in the root of the project being scanned to set defaults
without repeating flags every time — a CLI flag always overrides the file:

```toml
[pyaudit]
complexity_threshold = 10
coverage_target = 80
skip_coverage = false
min_score = 70

[pyaudit.ignore]
# Directory/file names to skip anywhere in the tree, in addition to the
# built-ins (venv, __pycache__, node_modules, build, dist, ...).
paths = ["migrations", "vendor"]
```

See this repo's own [`.pyaudit.toml`](.pyaudit.toml) for a real example — it
excludes `tests/fixtures/`, which is deliberately bad code used by the test
suite, from PyAudit's own self-audit.

The web UI is meant for local/dev use: it binds to `127.0.0.1` by default and
scans run with full filesystem access (including executing the target
project's own test suite for the coverage audit), so don't expose it to an
untrusted network without adding authentication in front of it. Each scan run
through the web UI can be viewed in-browser or downloaded as HTML/JSON, and a
per-session history of past scans is listed on the home page.

## Run tests

```bash
pytest
```

## What it checks

| Audit | Tool | What it finds |
|---|---|---|
| Complexity | radon | Functions too complex to safely change |
| Static analysis | pylint | Bugs, style issues, anti-patterns |
| Dead code | vulture | Unused functions/classes/variables draining maintainability |
| Security | bandit | SQL injection, `eval()`, shell injection, hardcoded secrets |
| Dependencies | pip-audit | Packages with known CVEs (`requirements.txt`, `pyproject.toml`, or `Pipfile`) |
| Coverage | coverage.py + pytest | Untested code paths |

## Not built yet

- Poetry's caret/tilde version ranges (`^1.2`, `~1.2`) have no exact pip
  equivalent, so they're scanned unpinned (see `dependencies.py`) rather than
  guessed — a real gap for CVEs that only affect part of the allowed range
- The web UI applies `.pyaudit.toml`'s `[pyaudit.ignore]` paths, but not its
  threshold/min-score fields — the web form's own fields take precedence there
- `pyaudit scan <github-url>` only supports the default branch, not
  `/tree/<branch>` URLs or private repos (no auth token support yet)
