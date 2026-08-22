# PyAudit — Automated Python Code Quality Reporter

One command. Six audits. One prioritized report (terminal, HTML, or JSON).

```bash
pip install -e .
pyaudit scan ./your-project
```

## Status

- [x] Package skeleton (`pyproject.toml`, installable via `pip install -e .`)
- [x] Typer CLI: `pyaudit scan <path>`, `pyaudit compare <before.json> <after.json>`
- [x] Complexity auditor (`radon`) — per-function cyclomatic complexity + risk rank,
      per-file maintainability index
- [x] Static analysis (`pylint`) — errors/warnings/conventions/refactors
- [x] Dead code detection (`vulture`) — unused functions, methods, variables
- [x] Security scanner (`bandit`) — OWASP-mapped findings by severity
- [x] Dependency audit (`pip-audit`) — CVEs against `requirements.txt`
- [x] Coverage reporter (`coverage.py` + `pytest`) — runs the target's own test suite
- [x] Health score (weighted across all six audits)
- [x] Rich terminal output
- [x] HTML report (self-contained, dark-mode, `--output report.html`)
- [x] JSON report (`--output report.json`, for CI / `compare`)
- [x] `--ci --min-score` quality gate
- [x] `pyaudit compare` for regression detection between two JSON reports

## A deviation from the original spec worth knowing about

The spec named `safety` for the dependency audit. I used **`pip-audit`** instead —
`safety`'s current CLI increasingly pushes users toward a paid/login-gated flow,
which conflicts with the "no API keys, zero cost" goal. `pip-audit` is MIT-licensed,
maintained by PyPA, needs no account, and queries the same class of vulnerability
databases (OSV + PyPI advisories). Swap it back to `safety` in
`pyaudit/audit/dependencies.py` if you'd rather match the spec verbatim.

Also: dependency scanning currently only reads `requirements.txt` (or
`requirements/base.txt`), not `pyproject.toml`/`Pipfile` — most portfolio-sized
repos use a requirements file, and extending this is a small, isolated change
later.

## Install (dev)

```bash
py -3 -m venv .venv
.venv\Scripts\Activate.ps1      # Windows PowerShell
pip install -e .
```

Installs all six audit tools (`radon`, `pylint`, `vulture`, `bandit`, `pip-audit`,
`coverage`) plus `pytest`, `typer`, `rich`, `jinja2` as real dependencies — nothing
extra to install by hand.

## Usage

```bash
# Terminal output only
pyaudit scan ./your-project

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
```

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
| Dependencies | pip-audit | Packages with known CVEs (via `requirements.txt`) |
| Coverage | coverage.py + pytest | Untested code paths |

## Not built yet

- `pyproject.toml` / `Pipfile` dependency extraction (requirements.txt only today)
- `pyaudit scan https://github.com/user/repo` (clone-and-scan a remote repo)
- `.pyaudit.toml` config file for per-project thresholds/ignores
- CI integration example (`.github/workflows/`)
