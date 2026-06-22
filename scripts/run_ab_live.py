"""T31 — run the live A/B harness against Odysseus and write a split ASR/FPR report.

Direct vs via the GuardrailEngine, using the red-team `Security_module` payloads as the oracle.
Usage:
    python scripts/run_ab_live.py
Env:
    GUARDRAILS_ENV_FALLBACK  — path to the eval-pipeline .env (ODYSSEUS_TOKEN/BASE_URL); defaults to
                               "../Agent evals/Agent eval pipeline/.env".
    SECURITY_MODULE_ROOT     — red-team repo root; defaults to the sibling Agent_security_testing path.
    AB_LIMIT_PER_CLASS       — optional int cap per attack suite (keeps a smoke run fast).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core.config import load_config  # noqa: E402
from eval.ab_harness import (  # noqa: E402
    build_live_arms,
    format_report,
    load_security_module_attacks,
    run_ab,
)

_DEFAULT_ENV = "../Agent evals/Agent eval pipeline/.env"
_DEFAULT_SECMOD = r"C:/Users/hp/Downloads/Agent_security_testing/Security_module"


def main() -> int:
    env_fallback = os.getenv("GUARDRAILS_ENV_FALLBACK", _DEFAULT_ENV)
    secmod_root = os.getenv("SECURITY_MODULE_ROOT", _DEFAULT_SECMOD)
    limit = os.getenv("AB_LIMIT_PER_CLASS")
    limit_per_class = int(limit) if limit else None

    config = load_config(fallback_path=env_fallback)
    print(f"[ab] target={config.odysseus_base_url}  secmod={secmod_root}")

    attacks, skipped = load_security_module_attacks(secmod_root, limit_per_class=limit_per_class)
    benign = json.loads((ROOT / "tests/fixtures/benign_prompts.json").read_text(encoding="utf-8"))
    print(f"[ab] attacks={len(attacks)}  benign={len(benign)}  skipped={len(skipped)}")

    direct, gateway = build_live_arms(config)

    t0 = time.time()
    report = run_ab(attacks, benign, direct, gateway)
    report.skipped = skipped
    elapsed = time.time() - t0

    text = format_report(report)
    print("\n" + text + f"\n\n[ab] {len(attacks)} attacks in {elapsed:.1f}s")

    out_dir = ROOT / "docs" / "eval"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ab_report.json").write_text(json.dumps(report.as_dict(), indent=2), encoding="utf-8")
    (out_dir / "ab_report.txt").write_text(text + "\n", encoding="utf-8")
    print(f"[ab] wrote {out_dir / 'ab_report.json'} and ab_report.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
