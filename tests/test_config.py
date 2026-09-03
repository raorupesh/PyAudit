from pyaudit.config import load_config


def test_load_config_missing_file_returns_defaults(tmp_path):
    config = load_config(tmp_path)

    assert config.complexity_threshold is None
    assert config.coverage_target is None
    assert config.skip_coverage is False
    assert config.ignore_paths == []
    assert config.loaded_from is None


def test_load_config_reads_values(tmp_path):
    (tmp_path / ".pyaudit.toml").write_text(
        "[pyaudit]\n"
        "complexity_threshold = 15\n"
        "coverage_target = 90\n"
        "min_score = 80\n"
        "skip_coverage = true\n"
        "\n"
        "[pyaudit.ignore]\n"
        'paths = ["migrations", "vendor"]\n',
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.complexity_threshold == 15
    assert config.coverage_target == 90
    assert config.min_score == 80
    assert config.skip_coverage is True
    assert config.ignore_paths == ["migrations", "vendor"]
    assert config.loaded_from == tmp_path / ".pyaudit.toml"


def test_load_config_malformed_toml_returns_defaults(tmp_path):
    (tmp_path / ".pyaudit.toml").write_text("not valid toml [[[", encoding="utf-8")

    config = load_config(tmp_path)

    assert config.loaded_from is None
    assert config.ignore_paths == []
