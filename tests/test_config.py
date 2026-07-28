import pytest

from sec_guardrails.core.config import ConfigError, load_config


def test_loads_from_env_dict():
    cfg = load_config(
        env={
            "ODYSSEUS_TOKEN": "t",
            "ODYSSEUS_BASE_URL": "http://x:7000/",
            "OPENAI_API_KEY": "k",
        }
    )
    assert cfg.odysseus_token == "t"
    assert cfg.odysseus_base_url == "http://x:7000"  # trailing slash stripped
    assert cfg.openai_api_key == "k"
    assert cfg.mistral_api_key is None


def test_missing_token_raises():
    with pytest.raises(ConfigError):
        load_config(env={})


def test_fallback_file_backfills(tmp_path):
    f = tmp_path / ".env"
    f.write_text('ODYSSEUS_TOKEN="fromfile"\n# comment\nMISTRAL_API_KEY=m\n', encoding="utf-8")
    cfg = load_config(env={}, fallback_path=str(f))
    assert cfg.odysseus_token == "fromfile"
    assert cfg.mistral_api_key == "m"


def test_env_wins_over_fallback(tmp_path):
    f = tmp_path / ".env"
    f.write_text("ODYSSEUS_TOKEN=fromfile\n", encoding="utf-8")
    cfg = load_config(env={"ODYSSEUS_TOKEN": "fromenv"}, fallback_path=str(f))
    assert cfg.odysseus_token == "fromenv"
