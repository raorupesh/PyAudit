from pathlib import Path

from pyaudit.audit.dependencies import analyze_dependencies

FIXTURES = Path(__file__).parent / "fixtures"


def test_analyze_dependencies_skips_when_no_requirements_file(tmp_path):
    result = analyze_dependencies(tmp_path)

    assert result.scanned is False
    assert result.vulnerable == []


def test_extract_pyproject_pep621_dependencies(tmp_path):
    from pyaudit.audit.dependencies import _extract_pyproject_dependencies

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "demo"\ndependencies = ["requests==2.25.0", "flask>=2.0"]\n',
        encoding="utf-8",
    )

    assert _extract_pyproject_dependencies(pyproject) == ["requests==2.25.0", "flask>=2.0"]


def test_extract_pyproject_poetry_dependencies(tmp_path):
    from pyaudit.audit.dependencies import _extract_pyproject_dependencies

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.poetry.dependencies]\npython = "^3.10"\nrequests = "2.25.0"\nflask = "^2.0"\n',
        encoding="utf-8",
    )

    deps = _extract_pyproject_dependencies(pyproject)

    assert "python" not in deps and not any(d.startswith("python") for d in deps)
    assert "requests" in deps  # bare version = Poetry's implicit caret -> left unpinned
    assert "flask" in deps  # explicit caret -> left unpinned


def test_extract_pyproject_returns_none_when_no_dependencies(tmp_path):
    from pyaudit.audit.dependencies import _extract_pyproject_dependencies

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[build-system]\nrequires = ["setuptools"]\n', encoding="utf-8")

    assert _extract_pyproject_dependencies(pyproject) is None


def test_extract_pipfile_dependencies(tmp_path):
    from pyaudit.audit.dependencies import _extract_pipfile_dependencies

    pipfile = tmp_path / "Pipfile"
    pipfile.write_text('[packages]\nrequests = "==2.25.0"\nflask = "*"\n', encoding="utf-8")

    deps = _extract_pipfile_dependencies(pipfile)

    assert "requests==2.25.0" in deps
    assert "flask" in deps


def test_analyze_dependencies_falls_back_to_pyproject_when_no_requirements_file(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = []\n', encoding="utf-8"
    )

    # An empty dependency list means _find_manifest finds nothing usable,
    # so this should behave exactly like "no manifest at all" rather than
    # invoking pip-audit.
    result = analyze_dependencies(tmp_path)

    assert result.scanned is False
