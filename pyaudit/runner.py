from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pyaudit.audit.complexity import analyze_complexity
from pyaudit.audit.coverage import analyze_coverage
from pyaudit.audit.deadcode import analyze_deadcode
from pyaudit.audit.dependencies import analyze_dependencies
from pyaudit.audit.security import analyze_security
from pyaudit.audit.static import analyze_static
from pyaudit.models import (
    AuditResults,
    ComplexityResult,
    CoverageResult,
    DeadCodeResult,
    DependencyResult,
    SecurityResult,
    StaticResult,
)


@dataclass
class ModuleWarning:
    module: str
    error: str


def run_audit(
    root: Path,
    complexity_threshold: int = 10,
    skip_coverage: bool = False,
    ignore_dirs: set[str] | None = None,
    on_stage: Callable[[str], None] | None = None,
) -> tuple[AuditResults, list[ModuleWarning]]:
    """Orchestrates all audit modules. Each module is isolated: if one tool
    crashes (missing binary, unsupported syntax, unexpected output), the rest
    of the audit still completes with an empty result for that module.

    `ignore_dirs`, if given, overrides each module's default ignore list
    (typically `fsutils.merge_ignore_dirs()` applied to a `.pyaudit.toml`
    config's `[pyaudit.ignore] paths`).

    `on_stage`, if given, is called with the name of each audit module right
    before it runs (used by the web UI to show live scan progress)."""
    warnings: list[ModuleWarning] = []

    def _safe(name, fn, empty):
        if on_stage:
            on_stage(name)
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - deliberately broad, see docstring
            warnings.append(ModuleWarning(module=name, error=str(e)))
            return empty

    complexity = _safe(
        "complexity",
        lambda: analyze_complexity(
            root,
            high_threshold=complexity_threshold,
            medium_threshold=complexity_threshold // 2,
            ignore_dirs=ignore_dirs,
        ),
        ComplexityResult(),
    )
    static = _safe("static", lambda: analyze_static(root, ignore_dirs=ignore_dirs), StaticResult())
    deadcode = _safe("deadcode", lambda: analyze_deadcode(root, ignore_dirs=ignore_dirs), DeadCodeResult())
    security = _safe("security", lambda: analyze_security(root, ignore_dirs=ignore_dirs), SecurityResult())
    dependencies = _safe("dependencies", lambda: analyze_dependencies(root), DependencyResult())

    if skip_coverage:
        if on_stage:
            on_stage("coverage")
        coverage = CoverageResult(available=False, reason="skipped (--skip-coverage)")
    else:
        coverage = _safe("coverage", lambda: analyze_coverage(root, ignore_dirs=ignore_dirs), CoverageResult())

    results = AuditResults(
        complexity=complexity,
        static=static,
        deadcode=deadcode,
        security=security,
        dependencies=dependencies,
        coverage=coverage,
    )
    return results, warnings
