import json
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

from pyaudit.models import DependencyResult, VulnerablePackage

REQUIREMENTS_CANDIDATES = ("requirements.txt", "requirements/base.txt")


def _find_requirements_file(root: Path) -> Path | None:
    for candidate in REQUIREMENTS_CANDIDATES:
        path = root / candidate
        if path.is_file():
            return path
    return None


def _poetry_constraint_to_pip(name: str, constraint) -> str:
    """Best-effort conversion of a Poetry-style dependency entry to a pip
    requirement line. Poetry's caret/tilde ranges (^1.2, ~1.2) have no exact
    pip equivalent, so those (and anything else that isn't already a plain
    pip specifier) are emitted as a bare, unpinned package name rather than
    mistranslated into the wrong version range."""
    if isinstance(constraint, dict):
        constraint = constraint.get("version", "")
    constraint = str(constraint or "").strip()
    if not constraint or constraint in ("*", "") or constraint[0] in "^~":
        return name
    if constraint[0] in "<>=!":
        return f"{name}{constraint}"
    return name


def _extract_pyproject_dependencies(pyproject_path: Path) -> list[str] | None:
    try:
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return None

    # PEP 621 — dependencies are already plain PEP 508 strings, pip-ready.
    project_deps = data.get("project", {}).get("dependencies")
    if project_deps:
        return [str(dep) for dep in project_deps]

    # Poetry — dependencies are a name -> constraint table, python excluded.
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies")
    if poetry_deps:
        return [
            _poetry_constraint_to_pip(name, constraint)
            for name, constraint in poetry_deps.items()
            if name.lower() != "python"
        ]

    return None


def _extract_pipfile_dependencies(pipfile_path: Path) -> list[str] | None:
    try:
        data = tomllib.loads(pipfile_path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return None

    packages = data.get("packages")
    if not packages:
        return None

    lines = []
    for name, constraint in packages.items():
        if isinstance(constraint, dict):
            constraint = constraint.get("version", "")
        constraint = str(constraint or "").strip()
        if not constraint or constraint == "*":
            lines.append(name)
        elif constraint[0] in "<>=!":
            lines.append(f"{name}{constraint}")
        else:
            lines.append(f"{name}=={constraint}")
    return lines


def _find_manifest(root: Path) -> tuple[Path, list[str]] | None:
    """Fallback used when there's no requirements.txt: extract dependencies
    from pyproject.toml (PEP 621 or Poetry) or Pipfile instead."""
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        deps = _extract_pyproject_dependencies(pyproject)
        if deps:
            return pyproject, deps

    pipfile = root / "Pipfile"
    if pipfile.is_file():
        deps = _extract_pipfile_dependencies(pipfile)
        if deps:
            return pipfile, deps

    return None


def analyze_dependencies(root: Path, timeout: int = 120) -> DependencyResult:
    """Run pip-audit (PyPI advisory DB + OSV, no login or API key required)
    and return packages with known CVEs.

    Reads requirements.txt / requirements/base.txt directly. When neither is
    present, falls back to extracting dependencies from pyproject.toml (PEP
    621 `[project.dependencies]` or Poetry's `[tool.poetry.dependencies]`) or
    Pipfile's `[packages]`, writing them to a temporary requirements-style
    file — pip-audit itself only understands requirements format.
    """
    req_file = _find_requirements_file(root)
    temp_req_file: Path | None = None

    if req_file is not None:
        source_label = req_file.name
    else:
        manifest = _find_manifest(root)
        if manifest is None:
            return DependencyResult(scanned=False)
        manifest_path, dep_lines = manifest
        source_label = manifest_path.name
        with tempfile.NamedTemporaryFile(
            mode="w", prefix="pyaudit-deps-", suffix=".txt", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write("\n".join(dep_lines))
            temp_req_file = Path(tmp.name)
        req_file = temp_req_file

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
        return DependencyResult(scanned=False, source_file=source_label)
    finally:
        if temp_req_file is not None:
            temp_req_file.unlink(missing_ok=True)

    try:
        payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        return DependencyResult(scanned=False, source_file=source_label)

    result = DependencyResult(scanned=True, source_file=source_label)
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
