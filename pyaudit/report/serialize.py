from dataclasses import asdict

from pyaudit.models import AuditResults


def results_to_dict(results: AuditResults, score: int) -> dict:
    """Flatten AuditResults + score into a plain JSON-serializable dict.

    `dataclasses.asdict` handles nested dataclasses, lists, and the Risk
    str-enum (str Enums serialize as their value automatically). Computed
    `@property` fields (counts, ratios) are added explicitly since asdict
    only walks declared fields.
    """
    payload = asdict(results)

    payload["complexity"]["total_functions"] = results.complexity.total_functions
    payload["complexity"]["high_count"] = results.complexity.high_count
    payload["complexity"]["medium_count"] = results.complexity.medium_count
    payload["complexity"]["low_count"] = results.complexity.low_count
    payload["complexity"]["average_complexity"] = round(results.complexity.average_complexity, 2)

    payload["static"]["error_count"] = results.static.error_count
    payload["static"]["warning_count"] = results.static.warning_count
    payload["static"]["convention_count"] = results.static.convention_count
    payload["static"]["refactor_count"] = results.static.refactor_count

    payload["deadcode"]["dead_lines"] = results.deadcode.dead_lines
    payload["deadcode"]["dead_ratio"] = round(results.deadcode.dead_ratio, 4)

    payload["security"]["high_count"] = results.security.high_count
    payload["security"]["medium_count"] = results.security.medium_count
    payload["security"]["low_count"] = results.security.low_count

    payload["dependencies"]["vulnerable_count"] = results.dependencies.vulnerable_count

    payload["health_score"] = score
    return payload
