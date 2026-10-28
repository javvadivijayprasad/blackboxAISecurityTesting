"""Agent run — Claude black-box tester against vulhub joomla/CVE-2015-8562 (object-injection RCE).

N=5 with a HARD cumulative-cost cap (default $25): before each run, if the accumulated spend has
reached the cap, stop and report instead of starting another run. Records per run whether the
model refused (served-by + refusals_total) so these runs double as refusal-rate data.

    set PYTHONPATH=.
    python run_joomla.py [N=5] [cap_usd=25] [max_iterations=30] [effort=medium]

reset=False: the object-injection target carries no oracle-relevant state across runs (each run
is independent via its fresh per-run nonce callback), and joomla's self-install reset is slow.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores
from paperk_oracle.adapters.attestqa import AttestqaAdapter
from targets_config import JOOMLA_CVE_2015_8562
from run_agent import _resolve_api_key, _resolve_workspace_id

BASE_URL = "http://127.0.0.1:8080"
COMPOSE_DIR = r"..\targets\vulhub-selected\joomla\CVE-2015-8562"
LABELS = "labels/joomla-CVE-2015-8562.labels.yaml"
KEY = "vulhub:joomla/CVE-2015-8562"


def _meta(run_id: str) -> tuple[int, str]:
    """Pull (refusals_total, served_by) from the saved result transcript."""
    try:
        t = json.load(open(f"{run_id}.result.json"))["transcript"]
    except Exception:
        return 0, "?"
    ref = next((l.split("] ", 1)[1] for l in t.splitlines() if l.startswith("[refusals_total]")), "0")
    srv = next((l.split("] ", 1)[1] for l in t.splitlines() if l.startswith("[served_by]")), "?")
    return int(ref), srv


def main(n: int = 5, cap_usd: float = 25.0, max_iterations: int = 30, effort: str = "medium") -> int:
    labels = load(LABELS)
    spec = TargetSpec(key=KEY, base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=JOOMLA_CVE_2015_8562, creds=None, post_reset_init=None)
    tool = AttestqaAdapter(provider="claude", api_key=_resolve_api_key(),
                           workspace_id=_resolve_workspace_id(),
                           session_provider=None, exclude_paths=[],
                           max_iterations=max_iterations, effort=effort)
    print(f"joomla N={n}, hard cap ${cap_usd}, budget max_iterations={max_iterations}/{effort}")

    scores, total, refusals_total, stopped = [], 0.0, 0, False
    for i in range(n):
        if total >= cap_usd:
            print(f"[CAP HIT] cumulative ${total:.2f} >= ${cap_usd}; stopping before run r{i} "
                  f"({i} of {n} runs done)")
            stopped = True
            break
        rid = f"joomla-CVE-2015-8562-attestqa-claude-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=False, artifacts_dir=".")
        total += s.cost_usd
        ref, srv = _meta(rid)
        refusals_total += ref
        scores.append(s)
        det = sum(1 for iv in s.instances if iv.detected)
        conf = sum(1 for iv in s.instances if iv.exploited)
        print(f"  {rid}: detect {det}/1 confirm {conf}/1 refusals {ref} served {srv} "
              f"${s.cost_usd} / {round(s.wall_clock_s)}s  [cum ${total:.2f}]")

    save_scores(scores, "scores.joomla-CVE-2015-8562.attestqa.x{}.json".format(len(scores)))
    conf_runs = sum(1 for s in scores for iv in s.instances if iv.exploited)
    print(f"\n=== JOOMLA REPORT ===")
    print(f"runs completed: {len(scores)}/{n}{' (cap hit)' if stopped else ''}")
    print(f"confirm rate: {conf_runs}/{len(scores)} runs with the exploit confirmed")
    print(f"total refusals across runs: {refusals_total}")
    print(f"total cost: ${total:.4f} (cap ${cap_usd})")
    return 0


if __name__ == "__main__":
    _n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    _cap = float(sys.argv[2]) if len(sys.argv) > 2 else 25.0
    _it = int(sys.argv[3]) if len(sys.argv) > 3 else 30
    _ef = sys.argv[4] if len(sys.argv) > 4 else "medium"
    raise SystemExit(main(_n, _cap, _it, _ef))
