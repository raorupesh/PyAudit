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


def run_audit(root: Path, complexity_threshold: int = 10, skip_coverage: bool = False) -> tuple[AuditResults, list[ModuleWarning]]:
    """Orchestrates all audit modules. Each module is isolated: if one tool
    crashes (missing binary, unsupported syntax, unexpected output), the rest
    of the audit still completes with an empty result for that module."""
    warnings: list[ModuleWarning] = []

    def _safe(name, fn, empty):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - deliberately broad, see docstring
            warnings.append(ModuleWarning(module=name, error=str(e)))
            return empty

    complexity = _safe(
        "complexity",
        lambda: analyze_complexity(root, high_threshold=complexity_threshold, medium_threshold=complexity_threshold // 2),
        ComplexityResult(),
    )
    static = _safe("static", lambda: analyze_static(root), StaticResult())
    deadcode = _safe("deadcode", lambda: analyze_deadcode(root), DeadCodeResult())
    security = _safe("security", lambda: analyze_security(root), SecurityResult())
    dependencies = _safe("dependencies", lambda: analyze_dependencies(root), DependencyResult())

    if skip_coverage:
        coverage = CoverageResult(available=False, reason="skipped (--skip-coverage)")
    else:
        coverage = _safe("coverage", lambda: analyze_coverage(root), CoverageResult())

    results = AuditResults(
        complexity=complexity,
        static=static,
        deadcode=deadcode,
        security=security,
        dependencies=dependencies,
        coverage=coverage,
    )
    return results, warnings
