"""Agent run — Claude black-box tester against vulhub phpmyadmin/WOOYUN-2016-199433.
GADGET-CONSTRUCTION CVE (expected to trigger refusals at serialized-object build).

Substitute for the kit's unavailable typecho/drupal-6340 gadget targets. Unauthenticated PHP
object injection via /scripts/setup.php; outcome is arbitrary file read (lfi.canary oracle).

Usage (ANTHROPIC_API_KEY env or .anthropic_key file; needs a workspace id for an org-level key):
    set PYTHONPATH=.
    python run_phpmyadmin_wooyun.py [repeats=3] [max_iterations=60] [effort=high]
"""
from __future__ import annotations
import sys
from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores, http_signature_check
from paperk_oracle.adapters.attestqa import AttestqaAdapter
from targets_config import PHPMYADMIN_WOOYUN_2016_199433
from run_agent import _resolve_api_key, _resolve_workspace_id

BASE_URL = "http://127.0.0.1:8095"
COMPOSE_DIR = r"..\targets\vulhub-selected\phpmyadmin\WOOYUN-2016-199433"
LABELS = "labels/phpmyadmin-WOOYUN-2016-199433.labels.yaml"
KEY = "vulhub:phpmyadmin/WOOYUN-2016-199433"


def main(repeats: int = 3, max_iterations: int = 60, effort: str = "high") -> int:
    labels = load(LABELS)
    spec = TargetSpec(key=KEY, base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=PHPMYADMIN_WOOYUN_2016_199433, creds=None, post_reset_init=None,
                      health_check=http_signature_check("phpMyAdmin"))
    tool = AttestqaAdapter(provider="claude", api_key=_resolve_api_key(),
                           workspace_id=_resolve_workspace_id(),
                           session_provider=None, exclude_paths=[],
                           max_iterations=max_iterations, effort=effort)
    print(f"phpmyadmin-WOOYUN-2016-199433 N={repeats}, budget max_iterations={max_iterations}/{effort}")
    reset = repeats > 1
    scores = []
    for i in range(repeats):
        rid = f"phpmyadmin-WOOYUN-2016-199433-attestqa-claude-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset, artifacts_dir=".")
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/{len(s.instances)}, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/{len(s.instances)}, "
              f"FP {s.false_positives}, ${s.cost_usd} / {round(s.wall_clock_s)}s")
    out = f"scores.phpmyadmin-WOOYUN-2016-199433.attestqa.x{repeats}.json"
    save_scores(scores, out)
    print(f"saved {out}: {len(scores)} run(s); total ${round(sum(s.cost_usd for s in scores),4)}")
    return 0


if __name__ == "__main__":
    _rep = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    _it = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    _eff = sys.argv[3] if len(sys.argv) > 3 else "high"
    raise SystemExit(main(_rep, _it, _eff))
