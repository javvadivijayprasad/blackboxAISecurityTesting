"""GPT-5.5 run — drupal/CVE-2018-7600 (Drupalgeddon2, one-shot RCE). Mirrors run_drupal_2018_7600.py."""
from __future__ import annotations
import sys

from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores, http_signature_check
from paperk_oracle.adapters.attestqa_openai import OpenAIAttestqaAdapter
from targets_config import DRUPAL_CVE_2018_7600, drupal_install

BASE_URL = "http://127.0.0.1:8094"
COMPOSE_DIR = r"..\targets\vulhub-selected\drupal\CVE-2018-7600"
LABELS = "labels/drupal-CVE-2018-7600.labels.yaml"
KEY = "vulhub:drupal/CVE-2018-7600"


def main(repeats: int = 3, max_iterations: int = 30, effort: str = "medium") -> int:
    labels = load(LABELS)
    spec = TargetSpec(key=KEY, base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=DRUPAL_CVE_2018_7600, creds=None,
                      post_reset_init=drupal_install("cve-2018-7600-web-1"),
                      health_check=http_signature_check("Drupal"))
    tool = OpenAIAttestqaAdapter(session_provider=None, exclude_paths=[],
                                 max_iterations=max_iterations, effort=effort)
    print(f"drupal-CVE-2018-7600 (gpt55) N={repeats}, budget max_iterations={max_iterations}/{effort}")
    reset = repeats > 1
    scores = []
    for i in range(repeats):
        rid = f"drupal-CVE-2018-7600-attestqa-gpt55-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset, artifacts_dir=".")
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/{len(s.instances)}, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/{len(s.instances)}, "
              f"FP {s.false_positives}, ${s.cost_usd} / {round(s.wall_clock_s)}s")
    out = f"scores.drupal-CVE-2018-7600.attestqa-gpt55.x{repeats}.json"
    save_scores(scores, out)
    print(f"saved {out}: {len(scores)} run(s); total ${round(sum(s.cost_usd for s in scores),4)}")
    return 0


if __name__ == "__main__":
    _rep = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    _it = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    _ef = sys.argv[3] if len(sys.argv) > 3 else "medium"
    raise SystemExit(main(_rep, _it, _ef))
