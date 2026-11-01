"""Agent run — Claude black-box tester against vulhub phpunit/CVE-2017-9841.
ONE-SHOT RCE CVE (single request; expected: no refusal).

Usage (ANTHROPIC_API_KEY env or .anthropic_key file):
    set PYTHONPATH=.
    python run_phpunit_2017_9841.py [repeats=3] [max_iterations=30] [effort=medium]
"""
from __future__ import annotations
import sys
from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores, http_signature_check
from paperk_oracle.adapters.attestqa import AttestqaAdapter
from targets_config import PHPUNIT_CVE_2017_9841
from run_agent import _resolve_api_key, _resolve_workspace_id

BASE_URL = "http://127.0.0.1:8093"
COMPOSE_DIR = r"..\targets\vulhub-selected\phpunit\CVE-2017-9841"
LABELS = "labels/phpunit-CVE-2017-9841.labels.yaml"
KEY = "vulhub:phpunit/CVE-2017-9841"


def main(repeats: int = 3, max_iterations: int = 30, effort: str = "medium") -> int:
    labels = load(LABELS)
    spec = TargetSpec(key=KEY, base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=PHPUNIT_CVE_2017_9841, creds=None, post_reset_init=None,
                      # root is 403 (no index); the eval-stdin endpoint returns 200 with X-Powered-By: PHP.
                      # This both waits for Apache to come up and confirms the phpunit container is answering.
                      health_check=http_signature_check(
                          "PHP", path="/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                          in_headers=True))
    tool = AttestqaAdapter(provider="claude", api_key=_resolve_api_key(),
                           workspace_id=_resolve_workspace_id(),
                           session_provider=None, exclude_paths=[],
                           max_iterations=max_iterations, effort=effort)
    print(f"phpunit-CVE-2017-9841 N={repeats}, budget max_iterations={max_iterations}/{effort}")
    reset = repeats > 1
    scores = []
    for i in range(repeats):
        rid = f"phpunit-CVE-2017-9841-attestqa-claude-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset, artifacts_dir=".")
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/{len(s.instances)}, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/{len(s.instances)}, "
              f"FP {s.false_positives}, ${s.cost_usd} / {round(s.wall_clock_s)}s")
    out = f"scores.phpunit-CVE-2017-9841.attestqa.x{repeats}.json"
    save_scores(scores, out)
    print(f"saved {out}: {len(scores)} run(s); total ${round(sum(s.cost_usd for s in scores),4)}")
    return 0


if __name__ == "__main__":
    _rep = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    _it = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    _eff = sys.argv[3] if len(sys.argv) > 3 else "medium"
    raise SystemExit(main(_rep, _it, _eff))
