from pathlib import Path

from vulture import Vulture

from pyaudit.fsutils import count_total_lines, iter_python_files, relative_path
from pyaudit.models import DeadCodeItem, DeadCodeResult


def analyze_deadcode(root: Path, min_confidence: int = 60, ignore_dirs: set[str] | None = None) -> DeadCodeResult:
    """Run vulture over root and return unused code items plus a dead-line ratio.

    Feeds vulture an explicit file list from iter_python_files rather than
    handing it the root directory + glob excludes: vulture's exclude patterns
    match against the full path, so a pattern like "*/venv/*" would wrongly
    exclude everything if root's own ancestry happens to contain "venv" —
    iter_python_files already gets this right by only checking components
    below root.
    """
    files = [str(f) for f in iter_python_files(root, ignore_dirs)]
    total_lines = count_total_lines(root, ignore_dirs)
    if not files:
        return DeadCodeResult(total_lines=total_lines)

    vulture = Vulture()
    try:
        vulture.scavenge(files)
    except Exception:
        return DeadCodeResult(total_lines=total_lines)

    result = DeadCodeResult(total_lines=total_lines)
    for item in vulture.get_unused_code(min_confidence=min_confidence):
        result.items.append(
            DeadCodeItem(
                file=relative_path(Path(item.filename), root),
                lineno=item.first_lineno,
                name=item.name,
                type=item.typ,
                confidence=item.confidence,
                size=item.size,
            )
        )

    return result
