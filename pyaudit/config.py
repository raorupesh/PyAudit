from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

CONFIG_FILENAME = ".pyaudit.toml"


@dataclass
class PyAuditConfig:
    """Per-project defaults loaded from `.pyaudit.toml` at the scanned
    project's root, if present. CLI flags always take precedence over these."""

    complexity_threshold: int | None = None
    coverage_target: int | None = None
    skip_coverage: bool = False
    min_score: int | None = None
    ignore_paths: list[str] = field(default_factory=list)
    loaded_from: Path | None = None


def load_config(root: Path) -> PyAuditConfig:
    """Read `<root>/.pyaudit.toml`. Missing file, unreadable file, or a
    malformed one all degrade to defaults rather than failing the scan.

    Expected shape:

        [pyaudit]
        complexity_threshold = 10
        coverage_target = 80
        skip_coverage = false
        min_score = 70

        [pyaudit.ignore]
        paths = ["migrations", "vendor"]
    """
    path = root / CONFIG_FILENAME
    if not path.is_file():
        return PyAuditConfig()

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return PyAuditConfig()

    section = data.get("pyaudit", {})
    if not isinstance(section, dict):
        return PyAuditConfig()
    ignore = section.get("ignore", {})

    return PyAuditConfig(
        complexity_threshold=section.get("complexity_threshold"),
        coverage_target=section.get("coverage_target"),
        skip_coverage=bool(section.get("skip_coverage", False)),
        min_score=section.get("min_score"),
        ignore_paths=list(ignore.get("paths", []) or []) if isinstance(ignore, dict) else [],
        loaded_from=path,
    )
