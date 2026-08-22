from pathlib import Path

from radon.complexity import cc_visit
from radon.metrics import mi_visit

from pyaudit.fsutils import DEFAULT_IGNORE_DIRS, iter_python_files, relative_path
from pyaudit.models import ComplexityResult, FileMaintainability, FunctionComplexity, Risk


def _classify(complexity: int, high_threshold: int, medium_threshold: int) -> Risk:
    if complexity > high_threshold:
        return Risk.HIGH
    if complexity > medium_threshold:
        return Risk.MEDIUM
    return Risk.LOW


def analyze_complexity(
    root: Path,
    high_threshold: int = 10,
    medium_threshold: int = 5,
    ignore_dirs: set[str] | None = None,
) -> ComplexityResult:
    """Run radon's cyclomatic complexity + maintainability index over every .py file under root."""
    ignore_dirs = ignore_dirs if ignore_dirs is not None else DEFAULT_IGNORE_DIRS
    result = ComplexityResult()

    for file_path in iter_python_files(root, ignore_dirs):
        try:
            source = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        rel_path = relative_path(file_path, root)

        try:
            blocks = cc_visit(source)
        except SyntaxError:
            continue

        for block in blocks:
            risk = _classify(block.complexity, high_threshold, medium_threshold)
            result.functions.append(
                FunctionComplexity(
                    file=rel_path,
                    name=block.name,
                    lineno=block.lineno,
                    complexity=block.complexity,
                    risk=risk,
                )
            )

        try:
            mi_score = mi_visit(source, multi=True)
        except SyntaxError:
            mi_score = None

        if mi_score is not None:
            result.files.append(FileMaintainability(file=rel_path, maintainability_index=round(mi_score, 2)))

    return result
