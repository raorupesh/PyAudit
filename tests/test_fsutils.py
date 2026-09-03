import zipfile

import pytest

from pyaudit.fsutils import DEFAULT_IGNORE_DIRS, extract_archive, is_github_url, merge_ignore_dirs


def test_is_github_url_accepts_github_com():
    assert is_github_url("https://github.com/psf/requests")
    assert is_github_url("http://www.github.com/psf/requests")


def test_is_github_url_rejects_non_github():
    assert not is_github_url("/local/path")
    assert not is_github_url("https://gitlab.com/psf/requests")


def test_merge_ignore_dirs_adds_extra_names():
    merged = merge_ignore_dirs(["migrations"])

    assert "migrations" in merged
    assert "venv" in merged


def test_merge_ignore_dirs_no_extra_returns_defaults():
    assert merge_ignore_dirs(None) == DEFAULT_IGNORE_DIRS
    assert merge_ignore_dirs([]) == DEFAULT_IGNORE_DIRS


def test_extract_archive_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("../../evil.txt", "pwned")

    destination = tmp_path / "dest"
    destination.mkdir()

    with pytest.raises(ValueError):
        extract_archive(archive_path, destination)


def test_extract_archive_extracts_normal_zip(tmp_path):
    archive_path = tmp_path / "good.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("project/app.py", "print('hi')")

    destination = tmp_path / "dest"
    destination.mkdir()

    result = extract_archive(archive_path, destination)

    assert (result / "app.py").read_text(encoding="utf-8") == "print('hi')"
