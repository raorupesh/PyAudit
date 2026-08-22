import json
import subprocess
import sys
from pathlib import Path

from pyaudit.fsutils import DEFAULT_IGNORE_DIRS
from pyaudit.models import StaticIssue, StaticResult

_CATEGORY_MAP = {
    "error": "error",
    "fatal": "error",
    "warning": "warning",
    "convention": "convention",
    "refactor": "refactor",
}


def analyze_static(root: Path, timeout: int = 120) -> StaticResult:
    """Run pylint over root and return categorized issues.

    Runs as a subprocess (rather than pylint's in-process API) so a pylint
    crash or a non-zero exit code (pylint exits non-zero whenever it finds
    issues) can never take down the rest of the audit.
    """
    try:
        proc = subprocess.run(
            [
                sys.executable, "-m", "pylint",
                "--output-format=json", "--recursive=y",
                f"--ignore={','.join(sorted(DEFAULT_IGNORE_DIRS))}",
                str(root),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return StaticResult()

    try:
        raw_issues = json.loads(proc.stdout) if proc.stdout.strip() else []
    except json.JSONDecodeError:
        return StaticResult()

    root_abs = root.resolve()
    result = StaticResult()
    for item in raw_issues:
        category = _CATEGORY_MAP.get(item.get("type", ""), "convention")
        # pylint always reports paths relative to the CWD it was run from,
        # not relative to the scanned root — re-anchor to root for display.
        try:
            abs_path = (Path.cwd() / item["path"]).resolve()
            file_path = str(abs_path.relative_to(root_abs))
        except (ValueError, KeyError):
            file_path = item.get("path", "")

        result.issues.append(
            StaticIssue(
                file=file_path,
                line=item.get("line", 0),
                column=item.get("column", 0),
                symbol=item.get("symbol", ""),
                message=item.get("message", ""),
                category=category,
            )
        )

    return result
