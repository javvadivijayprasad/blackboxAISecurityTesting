"""First graded run — ZAP baseline against DVWA (runbook step 6).

Usage:
    set PYTHONPATH=.
    python run_dvwa.py low          # Run A (vulnerable build) -> DVWA.low.labels.yaml
    python run_dvwa.py impossible   # Run B (control build)    -> DVWA.impossible.labels.yaml

Each level is a SEPARATE run (design s6): a run loads only its level's label file, so a true
detection is never also counted as a false positive. The ZAP daemon must be up first
(dockerctl.zap_up / zap_wait_ready, or `python -c "from paperk_oracle import dockerctl as d; d.zap_up(); d.zap_wait_ready()"`).
"""
from __future__ import annotations
import sys

from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores
from paperk_oracle.adapters.zap import ZapAdapter
from targets_config import (DVWA, dvwa_zap_session_setup, dvwa_reinit,
                            DVWA_ZAP_SEEDS, DVWA_ZAP_EXCLUDE)

ZAP_API = "http://127.0.0.1:8090"
ZAP_KEY = "paperk"
COMPOSE_DIR = r"..\targets\DVWA"
BASE_URL = "http://localhost:4280"


def main(level: str = "low", repeats: int = 1) -> int:
    if level not in ("low", "medium", "high", "impossible"):
        print(f"unknown level {level!r}"); return 2

    labels = load(f"labels/DVWA.{level}.labels.yaml")
    spec = TargetSpec(key="DVWA", base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=DVWA, creds={"user": "admin", "pass": "password"},
                      post_reset_init=dvwa_reinit)
    tool = ZapAdapter(ZAP_API, ZAP_KEY,
                      session_setup=dvwa_zap_session_setup(level),
                      seed_requests=DVWA_ZAP_SEEDS,
                      exclude_paths=DVWA_ZAP_EXCLUDE,
                      spider_timeout_min=3, ascan_timeout_min=45)

    reset = repeats > 1   # repeats: fresh reset+reinit between trials (single run stays on live)
    scores = []
    for i in range(repeats):
        rid = f"DVWA-{level}-zap-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset)
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/4, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/4, FP {s.false_positives}, "
              f"unscored {s.unscored}, {round(s.wall_clock_s)}s")

    out = f"scores.DVWA.{level}.zap{'.x'+str(repeats) if repeats > 1 else ''}.json"
    save_scores(scores, out)
    print(f"saved {out}: {len(scores)} run(s)")
    return 0


if __name__ == "__main__":
    lvl = sys.argv[1] if len(sys.argv) > 1 else "low"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    raise SystemExit(main(lvl, n))
