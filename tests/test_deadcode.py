from pathlib import Path

from pyaudit.audit.deadcode import analyze_deadcode

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_deadcode_finds_unused_items():
    result = analyze_deadcode(FIXTURES)

    names = {item.name for item in result.items}
    assert "unused_function" in names
    assert "unused_method" in names
    assert "unused_variable" in names
    assert "used_function" not in names

    assert result.total_lines > 0
    assert result.dead_lines > 0
    assert 0 < result.dead_ratio <= 1
