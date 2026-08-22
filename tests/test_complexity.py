from pathlib import Path

from pyaudit.audit.complexity import analyze_complexity
from pyaudit.models import Risk

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_complexity_flags_high_and_low_risk_functions():
    result = analyze_complexity(FIXTURES, high_threshold=10, medium_threshold=5)

    by_name = {f.name: f for f in result.functions if f.file == "high_complexity.py"}

    assert by_name["classify"].risk is Risk.HIGH
    assert by_name["classify"].complexity > 10

    assert by_name["simple"].risk is Risk.LOW
    assert by_name["simple"].complexity == 1


def test_complexity_result_aggregates():
    result = analyze_complexity(FIXTURES, high_threshold=10, medium_threshold=5)

    assert result.total_functions >= 2
    assert result.high_count >= 1
    assert result.average_complexity > 0
