import json
from pathlib import Path

import pytest

from core.native import HAVE_RUST, _py_redact_secrets, redact_secrets
from core.rail import Action, RailContext
from rails.input.secrets import SecretsRail

VECTORS = json.loads((Path(__file__).parent / "vectors" / "secrets.json").read_text("utf-8"))


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_redaction_matches_vectors(vec):
    out = redact_secrets(vec["input"])
    if vec["clean"]:
        assert out == vec["input"]
    else:
        assert out != vec["input"]
        for label in vec["expect_labels"]:
            assert f"[REDACTED:{label}]" in out


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_rust_python_parity(vec):
    """Active backend and the Python fallback must agree on every vector."""
    if not HAVE_RUST:
        pytest.skip("Rust extension not installed — parity checked in the rust-core CI lane")
    assert redact_secrets(vec["input"]) == _py_redact_secrets(vec["input"])


def test_rail_modifies_on_secret():
    decision = SecretsRail().inspect(RailContext(text="key sk-ABCDEFGHIJKLMNOPQRSTUV end"))
    assert decision.action is Action.MODIFY
    assert "[REDACTED:OPENAI_KEY]" in decision.modified


def test_rail_allows_clean_text():
    assert SecretsRail().inspect(RailContext(text="hello world")).action is Action.ALLOW
