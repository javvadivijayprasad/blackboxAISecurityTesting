"""GPT-5.5 run — OpenAI black-box tester against vulhub thinkphp/5-rce. Mirrors run_thinkphp.py.

Pipeline check for the cross-provider comparison. Same spec as the Claude run; only the adapter
and the run-id/output tags change (-> attestqa-gpt55), so it never overwrites the Claude results.

    (.venv_gpt55) ...> set OPENAI_API_KEY=sk-...
    (.venv_gpt55) ...> set PYTHONPATH=.
    (.venv_gpt55) ...> python run_thinkphp_gpt55.py [repeats] [max_iterations] [effort]
"""
from __future__ import annotations
import sys

from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores, http_signature_check
from paperk_oracle.adapters.attestqa_openai import OpenAIAttestqaAdapter
from targets_config import THINKPHP_5_RCE

BASE_URL = "http://127.0.0.1:8080"
COMPOSE_DIR = r"..\targets\vulhub-selected\thinkphp\5-rce"
LABELS = "labels/thinkphp-5-rce.labels.yaml"
KEY = "vulhub:thinkphp/5-rce"


def main(repeats: int = 1, max_iterations: int = 30, effort: str = "medium") -> int:
    labels = load(LABELS)
    spec = TargetSpec(key=KEY, base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=THINKPHP_5_RCE, creds=None, post_reset_init=None,
                      health_check=http_signature_check("ThinkPHP"))
    tool = OpenAIAttestqaAdapter(session_provider=None, exclude_paths=[],
                                 max_iterations=max_iterations, effort=effort)
    print(f"budget: max_iterations={max_iterations}, effort={effort}, model={tool.model}")

    reset = repeats > 1
    scores = []
    for i in range(repeats):
        rid = f"thinkphp-5-rce-attestqa-gpt55-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset, artifacts_dir=".")
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/{len(s.instances)}, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/{len(s.instances)}, "
              f"FP {s.false_positives}, ${s.cost_usd} / {round(s.wall_clock_s)}s")

    out = f"scores.thinkphp-5-rce.attestqa-gpt55{'.x'+str(repeats) if repeats > 1 else ''}.json"
    save_scores(scores, out)
    print(f"saved {out}: {len(scores)} run(s); total cost ${round(sum(s.cost_usd for s in scores), 4)}")
    return 0


if __name__ == "__main__":
    _rep = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    _iters = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    _eff = sys.argv[3] if len(sys.argv) > 3 else "medium"
    raise SystemExit(main(_rep, _iters, _eff))
