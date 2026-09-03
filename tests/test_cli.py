import typer
import pytest

from pyaudit.cli import _resolve_scan_target


def test_resolve_scan_target_valid_local_path(tmp_path):
    target, display_name, temp_root = _resolve_scan_target(str(tmp_path))

    assert target == tmp_path
    assert display_name == str(tmp_path)
    assert temp_root is None


def test_resolve_scan_target_missing_local_path_exits(tmp_path):
    with pytest.raises(typer.Exit):
        _resolve_scan_target(str(tmp_path / "does-not-exist"))


def test_resolve_scan_target_detects_github_url_without_network(monkeypatch, tmp_path):
    from pyaudit import fsutils

    def fake_resolve(url):
        return tmp_path, tmp_path

    monkeypatch.setattr(fsutils, "resolve_github_url", fake_resolve)

    target, display_name, temp_root = _resolve_scan_target("https://github.com/psf/requests")

    assert target == tmp_path
    assert display_name == "https://github.com/psf/requests"
    assert temp_root == tmp_path
