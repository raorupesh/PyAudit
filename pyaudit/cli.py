import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from pyaudit.models import Risk
from pyaudit.report.generator import generate_html
from pyaudit.report.serialize import results_to_dict
from pyaudit.runner import run_audit
from pyaudit.scorer import calculate_health_score

try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

app = typer.Typer(add_completion=False, help="Automated Python code quality reporter.")
console = Console()

RISK_COLOR = {Risk.HIGH: "red", Risk.MEDIUM: "yellow", Risk.LOW: "green"}
SEVERITY_COLOR = {"high": "red", "medium": "yellow", "low": "green"}
CATEGORY_COLOR = {"error": "red", "warning": "yellow", "refactor": "cyan", "convention": "green"}


def _score_color(score: int) -> str:
    if score > 80:
        return "green"
    if score >= 60:
        return "yellow"
    return "red"


def _print_complexity(complexity) -> None:
    console.print(f"[green]✓[/green] Complexity analysis    {complexity.total_functions} functions scanned")
    flagged = sorted(
        (f for f in complexity.functions if f.risk in (Risk.HIGH, Risk.MEDIUM)),
        key=lambda f: f.complexity,
        reverse=True,
    )
    if flagged:
        table = Table(title="Complexity findings")
        table.add_column("Risk")
        table.add_column("Complexity", justify="right")
        table.add_column("Function")
        table.add_column("Location")
        for f in flagged[:20]:
            color = RISK_COLOR[f.risk]
            table.add_row(f"[{color}]{f.risk.value.upper()}[/{color}]", str(f.complexity), f.name, f"{f.file}:{f.lineno}")
        console.print(table)
        if len(flagged) > 20:
            console.print(f"  … and {len(flagged) - 20} more")
    console.print(
        f"  {complexity.high_count} high, {complexity.medium_count} medium, "
        f"{complexity.low_count} low · avg complexity {complexity.average_complexity:.1f}"
    )


def _print_static(static) -> None:
    total = static.error_count + static.warning_count
    console.print(f"[green]✓[/green] Static analysis        {total} issues found ({static.error_count} errors, {static.warning_count} warnings)")
    if static.convention_count or static.refactor_count:
        console.print(f"  {static.convention_count} convention, {static.refactor_count} refactor suggestions (not shown)")


def _print_deadcode(deadcode) -> None:
    console.print(f"[green]✓[/green] Dead code detection    {len(deadcode.items)} unused items")
    if deadcode.items:
        table = Table(title="Dead code")
        table.add_column("Type")
        table.add_column("Name")
        table.add_column("Confidence", justify="right")
        table.add_column("Location")
        for d in deadcode.items[:20]:
            table.add_row(d.type, d.name, f"{d.confidence}%", f"{d.file}:{d.lineno}")
        console.print(table)
        if len(deadcode.items) > 20:
            console.print(f"  … and {len(deadcode.items) - 20} more")


def _print_security(security) -> None:
    total = security.high_count + security.medium_count + security.low_count
    console.print(
        f"[green]✓[/green] Security scan          {total} potential vulnerabilities "
        f"({security.high_count} high, {security.medium_count} medium, {security.low_count} low)"
    )
    high_and_medium = [i for i in security.issues if i.severity in ("high", "medium")]
    if high_and_medium:
        table = Table(title="Security findings")
        table.add_column("Severity")
        table.add_column("Issue")
        table.add_column("Location")
        for s in sorted(high_and_medium, key=lambda i: 0 if i.severity == "high" else 1)[:20]:
            color = SEVERITY_COLOR[s.severity]
            table.add_row(f"[{color}]{s.severity.upper()}[/{color}]", s.issue, f"{s.file}:{s.line}")
        console.print(table)


def _print_dependencies(dependencies) -> None:
    if not dependencies.scanned:
        console.print("[yellow]⚠[/yellow] Dependency audit       skipped (no requirements.txt found)")
        return
    console.print(f"[green]✓[/green] Dependency audit       {dependencies.vulnerable_count} vulnerable package(s)")
    for v in dependencies.vulnerable[:20]:
        console.print(f"  [red]{v.name}=={v.installed_version}[/red]  {v.vulnerability_id}  fix: {', '.join(v.fix_versions) or 'unknown'}")


def _print_coverage(coverage, target: int) -> None:
    if not coverage.available:
        console.print(f"[yellow]⚠[/yellow] Test coverage          unavailable ({coverage.reason or 'unknown reason'})")
        return
    color = "green" if coverage.overall_pct >= target else ("yellow" if coverage.overall_pct >= 40 else "red")
    console.print(f"[green]✓[/green] Test coverage          [{color}]{coverage.overall_pct}%[/{color}] (target: {target}%)")
    zero = coverage.zero_coverage_files
    if zero:
        console.print(f"  {len(zero)} file(s) with 0% coverage: " + ", ".join(f.file for f in zero[:10]))


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True, help="Path to the Python project to audit."),
    complexity_threshold: int = typer.Option(10, "--complexity-threshold", help="Cyclomatic complexity above which a function is flagged HIGH risk."),
    coverage_target: int = typer.Option(80, "--coverage-target", help="Target test coverage percentage used in scoring."),
    output: Path = typer.Option(None, "--output", help="Write a report to this path. Format is chosen by extension: .html or .json."),
    skip_coverage: bool = typer.Option(False, "--skip-coverage", help="Don't run the target's test suite under coverage (faster; skips the riskiest audit)."),
    ci: bool = typer.Option(False, "--ci", help="Exit with code 1 if the health score is below --min-score."),
    min_score: int = typer.Option(70, "--min-score", help="Minimum health score required when --ci is set."),
) -> None:
    """Run a full code quality audit on PATH."""
    console.print(f"[bold]Scanning[/bold] {path}\n")

    results, warnings = run_audit(path, complexity_threshold=complexity_threshold, skip_coverage=skip_coverage)
    score = calculate_health_score(results, coverage_target=coverage_target)

    for w in warnings:
        console.print(f"[yellow]⚠[/yellow] {w.module} audit failed and was skipped: {w.error}")

    _print_complexity(results.complexity)
    _print_static(results.static)
    _print_deadcode(results.deadcode)
    _print_security(results.security)
    _print_dependencies(results.dependencies)
    _print_coverage(results.coverage, coverage_target)

    color = _score_color(score)
    console.print(f"\n[bold]\U0001f4ca Overall health score:[/bold] [{color}]{score}/100[/{color}]")

    if output is not None:
        if output.suffix == ".json":
            output.write_text(json.dumps(results_to_dict(results, score), indent=2), encoding="utf-8")
        else:
            html = generate_html(results, score, project_name=str(path), coverage_target=coverage_target)
            output.write_text(html, encoding="utf-8")
        console.print(f"\U0001f4c4 Report written to: {output}")

    if ci and score < min_score:
        console.print(f"\n[red]CI check failed:[/red] health score {score} is below --min-score {min_score}")
        raise typer.Exit(code=1)


@app.command()
def compare(
    before: Path = typer.Argument(..., exists=True, help="Earlier report.json to compare from."),
    after: Path = typer.Argument(..., exists=True, help="Later report.json to compare against."),
) -> None:
    """Compare two JSON reports (from `pyaudit scan --output report.json`) and highlight regressions."""
    before_data = json.loads(before.read_text(encoding="utf-8"))
    after_data = json.loads(after.read_text(encoding="utf-8"))

    rows = [
        ("Health score", before_data.get("health_score", 0), after_data.get("health_score", 0), True),
        ("Complexity — high risk", before_data["complexity"]["high_count"], after_data["complexity"]["high_count"], False),
        ("Static — errors", before_data["static"]["error_count"], after_data["static"]["error_count"], False),
        ("Static — warnings", before_data["static"]["warning_count"], after_data["static"]["warning_count"], False),
        ("Dead code items", len(before_data["deadcode"]["items"]), len(after_data["deadcode"]["items"]), False),
        ("Security — high", before_data["security"]["high_count"], after_data["security"]["high_count"], False),
        ("Security — medium", before_data["security"]["medium_count"], after_data["security"]["medium_count"], False),
        ("Vulnerable dependencies", before_data["dependencies"]["vulnerable_count"], after_data["dependencies"]["vulnerable_count"], False),
    ]

    table = Table(title=f"{before.name} → {after.name}")
    table.add_column("Metric")
    table.add_column("Before", justify="right")
    table.add_column("After", justify="right")
    table.add_column("Change", justify="right")

    regressed = False
    for label, before_val, after_val, higher_is_better in rows:
        delta = after_val - before_val
        improved = (delta > 0) if higher_is_better else (delta < 0)
        worsened = (delta < 0) if higher_is_better else (delta > 0)
        if worsened:
            regressed = True
            change = f"[red]{delta:+d}[/red]"
        elif improved:
            change = f"[green]{delta:+d}[/green]"
        else:
            change = "0"
        table.add_row(label, str(before_val), str(after_val), change)

    console.print(table)
    if regressed:
        console.print("\n[red]Regressions detected.[/red]")
        raise typer.Exit(code=1)
    console.print("\n[green]No regressions.[/green]")


if __name__ == "__main__":
    app()
