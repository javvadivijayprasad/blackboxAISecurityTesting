"""Agent run — Claude black-box tester against vulhub laravel/CVE-2021-3129 (Ignition RCE).

Usage (ANTHROPIC_API_KEY env or .anthropic_key file):
    set PYTHONPATH=.
    python run_laravel.py        # single run on the live env (reset=False)
    python run_laravel.py 3      # N=3 repeats, reset+up between each

Unauthenticated target: the agent gets base_url + the callback URL only (no creds, no session
provider, no level). Single RCE label; confirmation via the per-run nonce callback.
"""
from __future__ import annotations
import sys

from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores
from paperk_oracle.adapters.attestqa import AttestqaAdapter
from targets_config import LARAVEL_CVE_2021_3129
from run_agent import _resolve_api_key, _resolve_workspace_id

BASE_URL = "http://127.0.0.1:8080"
COMPOSE_DIR = r"..\targets\vulhub-selected\laravel\CVE-2021-3129"
LABELS = "labels/laravel-CVE-2021-3129.labels.yaml"
KEY = "vulhub:laravel/CVE-2021-3129"


def main(repeats: int = 1, max_iterations: int = 30, effort: str = "medium") -> int:
    labels = load(LABELS)
    # No post_reset_init: the laravel env needs no schema re-create (reset = down -v && up).
    spec = TargetSpec(key=KEY, base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=LARAVEL_CVE_2021_3129, creds=None, post_reset_init=None)
    tool = AttestqaAdapter(provider="claude", api_key=_resolve_api_key(),
                           workspace_id=_resolve_workspace_id(),
                           session_provider=None, exclude_paths=[],
                           max_iterations=max_iterations, effort=effort)
    print(f"budget: max_iterations={max_iterations}, effort={effort}")

    reset = repeats > 1
    scores = []
    for i in range(repeats):
        rid = f"laravel-CVE-2021-3129-attestqa-claude-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset, artifacts_dir=".")
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/{len(s.instances)}, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/{len(s.instances)}, "
              f"FP {s.false_positives}, ${s.cost_usd} / {round(s.wall_clock_s)}s")

    out = f"scores.laravel-CVE-2021-3129.attestqa{'.x'+str(repeats) if repeats > 1 else ''}.json"
    save_scores(scores, out)
    print(f"saved {out}: {len(scores)} run(s); total cost ${round(sum(s.cost_usd for s in scores), 4)}")
    return 0


if __name__ == "__main__":
    _rep = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    _iters = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    _eff = sys.argv[3] if len(sys.argv) > 3 else "medium"
    raise SystemExit(main(_rep, _iters, _eff))
