from pathlib import Path

from pyaudit.audit.security import analyze_security

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_security_finds_shell_injection_and_eval():
    result = analyze_security(FIXTURES)

    security_issues = [i for i in result.issues if i.file.endswith("security_issues.py")]
    assert security_issues
    assert any("shell=True" in i.issue for i in security_issues)
    assert any(i.test_id == "B307" or "eval" in i.issue.lower() for i in security_issues)
    assert result.high_count >= 1
