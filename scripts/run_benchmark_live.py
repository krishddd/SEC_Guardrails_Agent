"""T32 — run the AgentDojo benchmark through the guarded A/B path against live Odysseus.

    python scripts/run_benchmark_live.py
Env:
    GUARDRAILS_ENV_FALLBACK  — eval-pipeline .env (default the sibling Agent eval pipeline .env).
    BENCH_LIMIT_PER_SUITE    — cap per suite (default 3, keeps the live run tractable).
    AB_USE_ML                — "1" to use the deberta-v3 detector instead of the heuristic.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Windows consoles default to cp1252 and choke on report glyphs; never let a print lose the run.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from core.config import load_config  # noqa: E402
from eval.ab_harness import build_live_arms, format_report, run_ab  # noqa: E402
from eval.benchmarks import load_agentdojo_cases  # noqa: E402

_DEFAULT_ENV = "../Agent evals/Agent eval pipeline/.env"


def main() -> int:
    env_fallback = os.getenv("GUARDRAILS_ENV_FALLBACK", _DEFAULT_ENV)
    limit = int(os.getenv("BENCH_LIMIT_PER_SUITE", "3"))
    use_ml = os.getenv("AB_USE_ML", "").lower() in ("1", "true", "yes")

    config = load_config(fallback_path=env_fallback)
    attacks, benign, skipped = load_agentdojo_cases(limit_per_suite=limit)
    if not attacks:
        print(f"[bench] no AgentDojo cases loaded: {skipped}")
        return 1
    print(
        f"[bench] target={config.odysseus_base_url}  ml={'deberta-v3' if use_ml else 'heuristic'}  "
        f"attacks={len(attacks)}  benign={len(benign)}  (limit/suite={limit})"
    )

    direct, gateway = build_live_arms(config, use_ml=use_ml)
    t0 = time.time()
    report = run_ab(attacks, benign, direct, gateway)
    report.skipped = skipped
    elapsed = time.time() - t0

    text = format_report(report).replace("Security_module direct", "AgentDojo direct")

    # Write FIRST — a console-encoding error must never discard a 10-minute live run.
    out_dir = ROOT / "docs" / "eval"
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = "_ml" if use_ml else ""
    (out_dir / f"agentdojo_report{suffix}.json").write_text(
        json.dumps(report.as_dict(), indent=2), encoding="utf-8"
    )
    (out_dir / f"agentdojo_report{suffix}.txt").write_text(text + "\n", encoding="utf-8")
    print("\n" + text + f"\n\n[bench] {len(attacks)} attacks in {elapsed:.1f}s")
    print(f"[bench] wrote {out_dir / f'agentdojo_report{suffix}.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
