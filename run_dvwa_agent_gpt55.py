"""GPT-5.5 agent run against DVWA (textbook target). Mirrors run_agent.py.
Only the adapter + run-id/output tags change (-> attestqa-gpt55); never overwrites Claude files.

    (.venv_gpt55) ...> set OPENAI_API_KEY=sk-...   &&   set PYTHONPATH=.
    python run_dvwa_agent_gpt55.py low          # vulnerable build
    python run_dvwa_agent_gpt55.py impossible   # control build
"""
from __future__ import annotations
import sys

from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores, http_signature_check
from paperk_oracle.adapters.attestqa_openai import OpenAIAttestqaAdapter
from targets_config import DVWA, dvwa_agent_session, dvwa_reinit, DVWA_ZAP_EXCLUDE

BASE_URL = "http://127.0.0.1:4280"
COMPOSE_DIR = r"..\targets\DVWA"


def main(level: str = "low", repeats: int = 1) -> int:
    if level not in ("low", "medium", "high", "impossible"):
        print(f"unknown level {level!r}"); return 2
    labels = load(f"labels/DVWA.{level}.labels.yaml")
    spec = TargetSpec(key="DVWA", base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=DVWA, creds={"user": "admin", "pass": "password"},
                      post_reset_init=dvwa_reinit, health_check=http_signature_check("DVWA"))
    tool = OpenAIAttestqaAdapter(session_provider=dvwa_agent_session(level),
                                 exclude_paths=DVWA_ZAP_EXCLUDE,
                                 max_iterations=30, effort="medium")
    print(f"DVWA {level} (gpt55) N={repeats}")
    reset = repeats > 1
    scores = []
    for i in range(repeats):
        rid = f"DVWA-{level}-attestqa-gpt55-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset, artifacts_dir=".")
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/4, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/4, FP {s.false_positives}, "
              f"${s.cost_usd} / {round(s.wall_clock_s)}s")
    out = f"scores.DVWA.{level}.attestqa-gpt55{'.x'+str(repeats) if repeats > 1 else ''}.json"
    save_scores(scores, out)
    total = sum(s.cost_usd for s in scores)
    print(f"saved {out}: {len(scores)} run(s); total cost ${round(total, 4)} / "
          f"{sum(s.cost_tokens for s in scores)} tok")
    return 0


if __name__ == "__main__":
    lvl = sys.argv[1] if len(sys.argv) > 1 else "low"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    raise SystemExit(main(lvl, n))
