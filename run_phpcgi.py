"""Agent run — Claude black-box tester against vulhub php/CVE-2012-1823 (PHP-CGI arg-injection RCE).

Usage:
    set PYTHONPATH=.
    python run_phpcgi.py [repeats] [max_iterations] [effort]

The MEDIUM-difficulty real CVE (between thinkphp's trivial GET and laravel's gadget chain):
a single POST, but needs the php-cgi query-string injection technique. Unauthenticated.
"""
from __future__ import annotations
import sys

from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores, http_signature_check
from paperk_oracle.adapters.attestqa import AttestqaAdapter
from targets_config import PHP_CVE_2012_1823
from run_agent import _resolve_api_key, _resolve_workspace_id

BASE_URL = "http://127.0.0.1:8080"
COMPOSE_DIR = r"..\targets\vulhub-selected\php\CVE-2012-1823"
LABELS = "labels/php-CVE-2012-1823.labels.yaml"
KEY = "vulhub:php/CVE-2012-1823"


def main(repeats: int = 1, max_iterations: int = 30, effort: str = "medium") -> int:
    labels = load(LABELS)
    spec = TargetSpec(key=KEY, base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=PHP_CVE_2012_1823, creds=None, post_reset_init=None,
                      health_check=http_signature_check("Your name is"))
    tool = AttestqaAdapter(provider="claude", api_key=_resolve_api_key(),
                           workspace_id=_resolve_workspace_id(),
                           session_provider=None, exclude_paths=[],
                           max_iterations=max_iterations, effort=effort)
    print(f"budget: max_iterations={max_iterations}, effort={effort}")

    reset = repeats > 1
    scores = []
    for i in range(repeats):
        rid = f"php-CVE-2012-1823-attestqa-claude-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset, artifacts_dir=".")
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/{len(s.instances)}, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/{len(s.instances)}, "
              f"FP {s.false_positives}, ${s.cost_usd} / {round(s.wall_clock_s)}s")

    out = f"scores.php-CVE-2012-1823.attestqa{'.x'+str(repeats) if repeats > 1 else ''}.json"
    save_scores(scores, out)
    print(f"saved {out}: {len(scores)} run(s); total cost ${round(sum(s.cost_usd for s in scores), 4)}")
    return 0


if __name__ == "__main__":
    _rep = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    _iters = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    _eff = sys.argv[3] if len(sys.argv) > 3 else "medium"
    raise SystemExit(main(_rep, _iters, _eff))
