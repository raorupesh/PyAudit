import json
import subprocess
import sys
from pathlib import Path

from pyaudit.fsutils import DEFAULT_IGNORE_DIRS
from pyaudit.models import SecurityIssue, SecurityResult


def analyze_security(root: Path, timeout: int = 120) -> SecurityResult:
    """Run bandit over root and return findings bucketed by severity."""
    try:
        proc = subprocess.run(
            [
                sys.executable, "-m", "bandit",
                "-r", str(root),
                "-f", "json", "-q",
                "-x", ",".join(sorted(DEFAULT_IGNORE_DIRS)),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return SecurityResult()

    try:
        payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        return SecurityResult()

    root_abs = root.resolve()
    result = SecurityResult()
    for item in payload.get("results", []):
        try:
            abs_path = (Path.cwd() / item["filename"]).resolve()
            file_path = str(abs_path.relative_to(root_abs))
        except (ValueError, KeyError):
            file_path = item.get("filename", "")

        result.issues.append(
            SecurityIssue(
                file=file_path,
                line=item.get("line_number", 0),
                severity=item.get("issue_severity", "LOW").lower(),
                confidence=item.get("issue_confidence", "LOW").lower(),
                test_id=item.get("test_id", ""),
                issue=item.get("issue_text", ""),
            )
        )

    return result
