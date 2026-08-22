from pathlib import Path

from pyaudit.audit.static import analyze_static

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_static_finds_missing_docstrings():
    result = analyze_static(FIXTURES)

    dead_code_issues = [i for i in result.issues if i.file.endswith("dead_code.py")]
    assert dead_code_issues
    assert any(i.symbol == "missing-function-docstring" for i in dead_code_issues)
    assert all(i.category in ("error", "warning", "convention", "refactor") for i in result.issues)
