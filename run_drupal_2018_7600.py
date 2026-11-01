"""Agent run — Claude black-box tester against vulhub drupal/CVE-2018-7600.
ONE-SHOT RCE CVE (single request; expected: no refusal).

Usage (ANTHROPIC_API_KEY env or .anthropic_key file):
    set PYTHONPATH=.
    python run_drupal_2018_7600.py [repeats=3] [max_iterations=30] [effort=medium]
"""
from __future__ import annotations
import sys
from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores, http_signature_check
from paperk_oracle.adapters.attestqa import AttestqaAdapter
from targets_config import DRUPAL_CVE_2018_7600, drupal_install
from run_agent import _resolve_api_key, _resolve_workspace_id

BASE_URL = "http://127.0.0.1:8094"
COMPOSE_DIR = r"..\targets\vulhub-selected\drupal\CVE-2018-7600"
LABELS = "labels/drupal-CVE-2018-7600.labels.yaml"
KEY = "vulhub:drupal/CVE-2018-7600"


def main(repeats: int = 3, max_iterations: int = 30, effort: str = "medium") -> int:
    labels = load(LABELS)
    spec = TargetSpec(key=KEY, base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=DRUPAL_CVE_2018_7600, creds=None,
                      # vulhub image ships uninstalled; (re)install standard+sqlite after each reset
                      # so /user/register exists — otherwise a "no exploit" would be a setup artifact.
                      post_reset_init=drupal_install("cve-2018-7600-web-1"),
                      health_check=http_signature_check("Drupal"))
    tool = AttestqaAdapter(provider="claude", api_key=_resolve_api_key(),
                           workspace_id=_resolve_workspace_id(),
                           session_provider=None, exclude_paths=[],
                           max_iterations=max_iterations, effort=effort)
    print(f"drupal-CVE-2018-7600 N={repeats}, budget max_iterations={max_iterations}/{effort}")
    reset = repeats > 1
    scores = []
    for i in range(repeats):
        rid = f"drupal-CVE-2018-7600-attestqa-claude-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset, artifacts_dir=".")
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/{len(s.instances)}, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/{len(s.instances)}, "
              f"FP {s.false_positives}, ${s.cost_usd} / {round(s.wall_clock_s)}s")
    out = f"scores.drupal-CVE-2018-7600.attestqa.x{repeats}.json"
    save_scores(scores, out)
    print(f"saved {out}: {len(scores)} run(s); total ${round(sum(s.cost_usd for s in scores),4)}")
    return 0


if __name__ == "__main__":
    _rep = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    _it = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    _eff = sys.argv[3] if len(sys.argv) > 3 else "medium"
    raise SystemExit(main(_rep, _it, _eff))
