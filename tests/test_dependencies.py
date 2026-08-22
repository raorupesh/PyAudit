from pathlib import Path

from pyaudit.audit.dependencies import analyze_dependencies

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_dependencies_skips_when_no_requirements_file(tmp_path):
    result = analyze_dependencies(tmp_path)

    assert result.scanned is False
    assert result.vulnerable == []
