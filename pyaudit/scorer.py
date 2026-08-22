from pyaudit.models import AuditResults


def calculate_health_score(results: AuditResults, coverage_target: int = 80) -> int:
    score = 100

    complexity = results.complexity
    if complexity.total_functions:
        high_complexity_ratio = complexity.high_count / complexity.total_functions
        score -= min(20, int(high_complexity_ratio * 100))

    static = results.static
    error_penalty = static.error_count * 5
    warning_penalty = static.warning_count * 1
    score -= min(20, error_penalty + warning_penalty)

    deadcode = results.deadcode
    if deadcode.total_lines:
        score -= min(10, int(deadcode.dead_ratio * 50))

    security = results.security
    score -= security.high_count * 10
    score -= security.medium_count * 3

    dependencies = results.dependencies
    score -= dependencies.vulnerable_count * 5

    coverage = results.coverage
    if coverage.available:
        coverage_gap = max(0, coverage_target - coverage.overall_pct)
        score -= min(15, int(coverage_gap / 5))

    return max(0, score)
