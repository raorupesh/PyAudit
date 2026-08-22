from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pyaudit.models import AuditResults, Risk

TEMPLATE_DIR = Path(__file__).parent / "templates"

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
_STATIC_RANK = {"error": 0, "warning": 1, "refactor": 2, "convention": 3}


def _build_summary(results: AuditResults, score: int) -> list[str]:
    sentences = []

    if score > 80:
        sentences.append(f"Overall health score is {score}/100 — in good shape.")
    elif score >= 60:
        sentences.append(f"Overall health score is {score}/100 — some issues worth addressing.")
    else:
        sentences.append(f"Overall health score is {score}/100 — needs attention before this ships.")

    if results.security.high_count:
        sentences.append(f"{results.security.high_count} high-severity security finding(s) should be fixed first.")
    elif results.complexity.high_count:
        sentences.append(f"{results.complexity.high_count} function(s) are complex enough to be risky to change.")
    elif results.dependencies.vulnerable_count:
        sentences.append(f"{results.dependencies.vulnerable_count} dependency/dependencies have known vulnerabilities.")

    if results.coverage.available:
        sentences.append(f"Test coverage is {results.coverage.overall_pct}%.")
    else:
        sentences.append(f"Test coverage could not be measured ({results.coverage.reason or 'no tests found'}).")

    return sentences


def generate_html(results: AuditResults, score: int, project_name: str, coverage_target: int = 80) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")

    complexity_flagged = sorted(
        (f for f in results.complexity.functions if f.risk in (Risk.HIGH, Risk.MEDIUM)),
        key=lambda f: f.complexity,
        reverse=True,
    )
    static_issues = sorted(
        (i for i in results.static.issues if i.category in ("error", "warning")),
        key=lambda i: _STATIC_RANK.get(i.category, 9),
    )
    security_issues = sorted(results.security.issues, key=lambda i: _SEVERITY_RANK.get(i.severity, 9))
    coverage_files = sorted(results.coverage.files, key=lambda f: f.percent_covered)

    return template.render(
        project_name=project_name,
        results=results,
        score=score,
        coverage_target=coverage_target,
        summary=_build_summary(results, score),
        complexity_flagged=complexity_flagged,
        static_issues=static_issues,
        security_issues=security_issues,
        coverage_files=coverage_files,
    )
