import json
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

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


def merge_ignore_dirs(extra: list[str] | None) -> set[str]:
    """Combine the built-in ignore list with extra names from `.pyaudit.toml`
    (`[pyaudit.ignore] paths = [...]`). Entries are directory/file *names*
    matched anywhere in the tree — the same semantics as the built-in
    defaults — not path globs."""
    if not extra:
        return DEFAULT_IGNORE_DIRS
    return DEFAULT_IGNORE_DIRS | set(extra)


def is_github_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return parsed.scheme in ("http", "https") and parsed.netloc.lower() in {"github.com", "www.github.com"}


def _reject_unsafe_members(names: list[str], destination: Path) -> None:
    """Guard against zip-slip / tar path traversal: a member name containing
    `../` (or an absolute path) could otherwise write outside `destination`."""
    dest = destination.resolve()
    for name in names:
        if (dest / name).resolve() == dest or dest in (dest / name).resolve().parents:
            continue
        raise ValueError(f"Archive contains an unsafe path outside the destination: {name!r}")


def extract_archive(archive_path: Path, destination: Path) -> Path:
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            _reject_unsafe_members(archive.namelist(), destination)
            archive.extractall(destination)  # nosec B202 - member paths validated above
    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as archive:
            _reject_unsafe_members(archive.getnames(), destination)
            archive.extractall(destination)  # nosec B202 - member paths validated above
    else:
        raise ValueError("Unsupported archive type. Upload a .zip, .tar.gz, or .tgz file.")

    children = [p for p in destination.iterdir() if not p.name.startswith('.')]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return destination


def resolve_github_url(repo_url: str) -> tuple[Path, Path]:
    """Download and extract a GitHub repo's default branch to a temp directory.

    Returns `(project_dir, temp_root)` — `project_dir` is where the scan
    should point, `temp_root` is the directory the caller should clean up
    (it may be an ancestor of `project_dir` when the archive contained a
    single nested top-level folder, as GitHub's archives always do).
    """
    parsed = urlparse(repo_url.strip())
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("Only GitHub repository URLs are supported.")

    parts = [part for part in parsed.path.split('/') if part and part != '.git']
    if len(parts) < 2:
        raise ValueError("Use a GitHub URL in the form https://github.com/owner/repo.")

    owner, repo = parts[:2]
    repo = repo.removesuffix('.git')
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    api_request = Request(api_url, headers={"Accept": "application/vnd.github+json", "User-Agent": "PyAudit"})
    with urlopen(api_request, timeout=30) as response:  # nosec B310 - scheme/host are hardcoded https://api.github.com above
        payload = json.load(response)

    default_branch = payload.get("default_branch") or "main"
    archive_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{default_branch}.zip"

    temp_dir = Path(tempfile.mkdtemp(prefix="pyaudit-github-"))
    archive_path = temp_dir / f"{repo}-{default_branch}.zip"
    with urlopen(archive_url, timeout=60) as response, open(archive_path, "wb") as fh:  # nosec B310 - scheme/host are hardcoded https://github.com above
        shutil.copyfileobj(response, fh)

    return extract_archive(archive_path, temp_dir), temp_dir
