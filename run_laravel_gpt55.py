"""GPT-5.5 run — laravel/CVE-2021-3129 (Ignition phar-gadget RCE). Mirrors run_laravel.py.
Hard cost cap + per-run refusal tracking retained."""
from __future__ import annotations
import json
import sys

from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores, http_signature_check
from paperk_oracle.adapters.attestqa_openai import OpenAIAttestqaAdapter
from targets_config import LARAVEL_CVE_2021_3129

BASE_URL = "http://127.0.0.1:8080"
COMPOSE_DIR = r"..\targets\vulhub-selected\laravel\CVE-2021-3129"
LABELS = "labels/laravel-CVE-2021-3129.labels.yaml"
KEY = "vulhub:laravel/CVE-2021-3129"


def _meta(run_id: str) -> tuple[int, str]:
    try:
        t = json.load(open(f"{run_id}.result.json"))["transcript"]
    except Exception:
        return 0, "?"
    ref = next((l.split("] ", 1)[1] for l in t.splitlines() if l.startswith("[refusals_total]")), "0")
    srv = next((l.split("] ", 1)[1] for l in t.splitlines() if l.startswith("[served_by]")), "?")
    return int(ref), srv


def main(n: int = 3, cap_usd: float = 20.0, max_iterations: int = 60, effort: str = "high") -> int:
    labels = load(LABELS)
    spec = TargetSpec(key=KEY, base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=LARAVEL_CVE_2021_3129, creds=None, post_reset_init=None,
                      health_check=http_signature_check("Laravel"))
    tool = OpenAIAttestqaAdapter(session_provider=None, exclude_paths=[],
                                 max_iterations=max_iterations, effort=effort)
    print(f"laravel (gpt55) N={n}, hard cap ${cap_usd}, budget max_iterations={max_iterations}/{effort}")
    scores, total, refusals_total, stopped = [], 0.0, 0, False
    for i in range(n):
        if total >= cap_usd:
            print(f"[CAP HIT] cumulative ${total:.2f} >= ${cap_usd}; stopping before run r{i}")
            stopped = True
            break
        rid = f"laravel-CVE-2021-3129-attestqa-gpt55-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=True, artifacts_dir=".")
        total += s.cost_usd
        ref, srv = _meta(rid)
        refusals_total += ref
        scores.append(s)
        det = sum(1 for iv in s.instances if iv.detected)
        conf = sum(1 for iv in s.instances if iv.exploited)
        print(f"  {rid}: detect {det}/1 confirm {conf}/1 refusals {ref} served {srv} "
              f"${s.cost_usd} / {round(s.wall_clock_s)}s  [cum ${total:.2f}]")
    save_scores(scores, "scores.laravel-CVE-2021-3129.attestqa-gpt55.x{}.json".format(len(scores)))
    conf_runs = sum(1 for s in scores for iv in s.instances if iv.exploited)
    det_runs = sum(1 for s in scores for iv in s.instances if iv.detected)
    print(f"\n=== LARAVEL (gpt55) REPORT ===")
    print(f"runs completed: {len(scores)}/{n}{' (cap hit)' if stopped else ''}")
    print(f"detect: {det_runs}/{len(scores)}; confirm: {conf_runs}/{len(scores)}")
    print(f"total refusals across runs: {refusals_total}")
    print(f"total cost: ${total:.4f} (cap ${cap_usd})")
    return 0


if __name__ == "__main__":
    _n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    _cap = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
    _it = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    _ef = sys.argv[4] if len(sys.argv) > 4 else "high"
    raise SystemExit(main(_n, _cap, _it, _ef))
