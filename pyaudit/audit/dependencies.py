import json
import subprocess
import sys
from pathlib import Path

from pyaudit.models import DependencyResult, VulnerablePackage

REQUIREMENTS_CANDIDATES = ("requirements.txt", "requirements/base.txt")


def _find_requirements_file(root: Path) -> Path | None:
    for candidate in REQUIREMENTS_CANDIDATES:
        path = root / candidate
        if path.is_file():
            return path
    return None


def analyze_dependencies(root: Path, timeout: int = 120) -> DependencyResult:
    """Run pip-audit against the project's requirements.txt (PyPI advisory DB + OSV,
    no login or API key required) and return packages with known CVEs.

    Only requirements.txt-style files are supported today; pyproject.toml /
    Pipfile dependency extraction is a documented gap (see README).
    """
    req_file = _find_requirements_file(root)
    if req_file is None:
        return DependencyResult(scanned=False)

    try:
        proc = subprocess.run(
            [
                sys.executable, "-m", "pip_audit",
                "-r", str(req_file),
                "-f", "json",
                "--progress-spinner=off",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return DependencyResult(scanned=False, source_file=str(req_file.name))

    try:
        payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        return DependencyResult(scanned=False, source_file=str(req_file.name))

    result = DependencyResult(scanned=True, source_file=req_file.name)
    for dep in payload.get("dependencies", []):
        for vuln in dep.get("vulns", []) or []:
            result.vulnerable.append(
                VulnerablePackage(
                    name=dep.get("name", ""),
                    installed_version=dep.get("version", ""),
                    vulnerability_id=vuln.get("id", ""),
                    fix_versions=vuln.get("fix_versions", []),
                    description=(vuln.get("description") or "")[:300],
                )
            )

    return result
