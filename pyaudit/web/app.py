import json
import shutil
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request
from jinja2 import ChoiceLoader, FileSystemLoader

from pyaudit.config import load_config
from pyaudit.fsutils import extract_archive, merge_ignore_dirs, resolve_github_url
from pyaudit.models import AuditResults
from pyaudit.report.generator import TEMPLATE_DIR as REPORT_TEMPLATE_DIR
from pyaudit.report.generator import build_report_context, generate_html
from pyaudit.report.serialize import results_to_dict
from pyaudit.runner import ModuleWarning, run_audit
from pyaudit.scorer import calculate_health_score

WEB_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _safe_name(name: str) -> str:
    cleaned = ''.join(ch if ch.isalnum() or ch in {'-', '_', '.'} else '_' for ch in name).strip()
    return cleaned or 'project'


def _prepare_scan_target(raw_path: str, github_url: str, code_snippet: str, uploaded_file) -> Path:
    source = (raw_path or '').strip()
    github = (github_url or '').strip()
    snippet = (code_snippet or '').strip()

    if source:
        target = Path(source).expanduser()
        if not target.is_dir():
            raise ValueError(f"'{source}' is not a directory that exists on this machine.")
        return target

    if github:
        return resolve_github_url(github)[0]

    if uploaded_file and getattr(uploaded_file, 'filename', None):
        filename = uploaded_file.filename or "project.zip"
        temp_dir = Path(tempfile.mkdtemp(prefix="pyaudit-upload-"))
        archive_path = temp_dir / _safe_name(filename)
        uploaded_file.save(archive_path)

        if archive_path.suffix.lower() == ".py":
            project_dir = temp_dir / "project"
            project_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(archive_path, project_dir / archive_path.name)
            return project_dir

        return extract_archive(archive_path, temp_dir)

    if snippet:
        project_dir = Path(tempfile.mkdtemp(prefix="pyaudit-snippet-"))
        (project_dir / "app.py").write_text(snippet, encoding="utf-8")
        return project_dir

    raise ValueError("Provide a project path, GitHub URL, uploaded archive, or pasted Python code.")


@dataclass
class ScanRecord:
    id: str
    path: str
    score: int
    created_at: str
    results: AuditResults
    coverage_target: int
    warnings: list[ModuleWarning] = field(default_factory=list)


def create_app() -> Flask:
    app = Flask(__name__)
    app.jinja_loader = ChoiceLoader([
        FileSystemLoader(str(WEB_TEMPLATE_DIR)),
        FileSystemLoader(str(REPORT_TEMPLATE_DIR)),
    ])

    scans: dict[str, ScanRecord] = {}
    jobs: dict[str, dict] = {}

    def _int_field(name: str, default: int) -> int:
        try:
            return int(request.form.get(name, default))
        except ValueError:
            return default

    def _run_job(job_id: str, target: Path, complexity_threshold: int, coverage_target: int, skip_coverage: bool) -> None:
        def on_stage(name: str) -> None:
            jobs[job_id]["stage"] = name

        try:
            config = load_config(target)
            results, warnings = run_audit(
                target,
                complexity_threshold=complexity_threshold,
                skip_coverage=skip_coverage,
                ignore_dirs=merge_ignore_dirs(config.ignore_paths),
                on_stage=on_stage,
            )
            score = calculate_health_score(results, coverage_target=coverage_target)
            scan_id = uuid.uuid4().hex[:12]
            scans[scan_id] = ScanRecord(
                id=scan_id,
                path=str(target),
                score=score,
                created_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
                results=results,
                coverage_target=coverage_target,
                warnings=warnings,
            )
            jobs[job_id].update(status="done", stage="done", scan_id=scan_id)
        except Exception as e:  # noqa: BLE001 - reported to the browser, not swallowed
            jobs[job_id].update(status="error", error=str(e))

    @app.get("/")
    def index():
        history = sorted(scans.values(), key=lambda s: s.created_at, reverse=True)
        return render_template("index.html.j2", history=history)

    @app.post("/scan")
    def run_scan():
        try:
            target = _prepare_scan_target(
                request.form.get("path", ""),
                request.form.get("github_url", ""),
                request.form.get("paste_code", ""),
                request.files.get("source_file"),
            )
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

        complexity_threshold = _int_field("complexity_threshold", 10)
        coverage_target = _int_field("coverage_target", 80)
        skip_coverage = request.form.get("skip_coverage") == "on"

        job_id = uuid.uuid4().hex[:12]
        jobs[job_id] = {"status": "running", "stage": "queued"}
        thread = threading.Thread(
            target=_run_job,
            args=(job_id, target, complexity_threshold, coverage_target, skip_coverage),
            daemon=True,
        )
        thread.start()
        return jsonify(job_id=job_id)

    @app.get("/scan/<job_id>/status")
    def scan_status(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            abort(404)
        return jsonify(**job)

    @app.get("/report/<scan_id>")
    def view_report(scan_id: str):
        record = scans.get(scan_id)
        if record is None:
            abort(404)
        context = build_report_context(record.results, record.score, record.path, record.coverage_target)
        return render_template("report.html.j2", scan_id=scan_id, warnings=record.warnings, **context)

    @app.get("/report/<scan_id>/download/<fmt>")
    def download(scan_id: str, fmt: str):
        record = scans.get(scan_id)
        if record is None:
            abort(404)
        if fmt == "json":
            body = json.dumps(results_to_dict(record.results, record.score), indent=2)
            headers = {"Content-Disposition": f'attachment; filename="pyaudit-{scan_id}.json"'}
            return Response(body, mimetype="application/json", headers=headers)
        if fmt == "html":
            body = generate_html(record.results, record.score, record.path, record.coverage_target)
            headers = {"Content-Disposition": f'attachment; filename="pyaudit-{scan_id}.html"'}
            return Response(body, mimetype="text/html", headers=headers)
        abort(404)

    return app
