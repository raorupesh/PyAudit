from pathlib import Path

DEFAULT_IGNORE_DIRS = {
    "venv", ".venv", "__pycache__", ".git", "node_modules",
    "build", "dist", ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
}


def iter_python_files(root: Path, ignore_dirs: set[str] | None = None):
    """Yield every .py file under root, skipping ignored directory names.

    Only checks path components *below* root — an ignored name appearing in
    root's own ancestry (e.g. scanning a project that happens to live inside
    a folder called "venv" or "site-packages") must not exclude everything.
    """
    ignore_dirs = ignore_dirs if ignore_dirs is not None else DEFAULT_IGNORE_DIRS
    for path in root.rglob("*.py"):
        rel_parts = path.relative_to(root).parts
        if any(part in ignore_dirs for part in rel_parts):
            continue
        yield path


def relative_path(file_path: Path, root: Path) -> str:
    try:
        return str(file_path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(file_path)


def count_total_lines(root: Path, ignore_dirs: set[str] | None = None) -> int:
    total = 0
    for file_path in iter_python_files(root, ignore_dirs):
        try:
            total += sum(1 for _ in file_path.open(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    return total
