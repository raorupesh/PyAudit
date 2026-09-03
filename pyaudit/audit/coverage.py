import json
import subprocess
import sys
from pathlib import Path

from pyaudit.fsutils import DEFAULT_IGNORE_DIRS
from pyaudit.models import CoverageResult, FileCoverage


def analyze_coverage(root: Path, timeout: int = 120, ignore_dirs: set[str] | None = None) -> CoverageResult:
    """Discover and run the project's own pytest suite under coverage.py.

    This is the least reliable audit: it executes third-party test code in
    our own interpreter, which only works if that project's dependencies are
    importable here. Any failure degrades to `available=False` with a reason
    rather than aborting the whole scan.
    """
    ignore_dirs = ignore_dirs if ignore_dirs is not None else DEFAULT_IGNORE_DIRS
    data_file = root / ".pyaudit_coverage_tmp"
    omit = ",".join(f"*/{name}/*" for name in sorted(ignore_dirs))

    try:
        run_proc = subprocess.run(
            [
                sys.executable, "-m", "coverage", "run", f"--data-file={data_file}",
                "--source=.", f"--omit={omit}", "-m", "pytest", "-q",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CoverageResult(available=False, reason="test suite timed out")
    except OSError as e:
        return CoverageResult(available=False, reason=str(e))

    if "no tests ran" in (run_proc.stdout + run_proc.stderr).lower():
        return CoverageResult(available=False, reason="no tests found")

    try:
        json_proc = subprocess.run(
            [sys.executable, "-m", "coverage", "json", f"--data-file={data_file}", "-o", "-"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return CoverageResult(available=False, reason=str(e))
    finally:
        data_file.unlink(missing_ok=True)

    try:
        payload = json.loads(json_proc.stdout) if json_proc.stdout.strip() else None
    except json.JSONDecodeError:
        payload = None

    if payload is None:
        return CoverageResult(available=False, reason="could not run tests under coverage")

    files = [
        FileCoverage(
            file=path,
            percent_covered=round(info["summary"]["percent_covered"], 1),
            missing_lines=info.get("missing_lines", []),
        )
        for path, info in payload.get("files", {}).items()
    ]

    return CoverageResult(
        available=True,
        overall_pct=round(payload.get("totals", {}).get("percent_covered", 0.0), 1),
        files=files,
    )
