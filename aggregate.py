"""Cross-target/-tool aggregator — rolls every scores.*.json into Paper K's headline tables.

Reads all RunScore files in the cwd (scores.*.json), groups by (target, tool), and reports,
across the N runs in each group: per-class detection (TP/FP/FN -> P/R/F1), exploit-success
(mean confirmed / vulnerable instances) with pass@k, false positives, and cost. No LLM, no
network; pure read of the released records.

Usage:  PYTHONPATH=. python aggregate.py
"""
from __future__ import annotations
import glob
import json
import statistics as st
from collections import defaultdict


def _mean_sd(xs):
    return (st.mean(xs), (st.pstdev(xs) if len(xs) > 1 else 0.0)) if xs else (0.0, 0.0)


def main() -> int:
    runs = []
    for f in sorted(glob.glob("scores.*.json")):
        try:
            for s in json.load(open(f)):
                runs.append(s)
        except Exception as e:
            print(f"! skip {f}: {e}")
    if not runs:
        print("no scores.*.json found"); return 1

    # The DVWA security level lives in the run_id (e.g. DVWA-low-...), not the RunScore, so
    # parse it out and group by it — otherwise low and impossible runs average together.
    def level_of(run_id: str) -> str:
        toks = run_id.split("-")
        for lv in ("low", "impossible", "medium", "high"):
            if lv in toks:
                return lv
        return "-"

    groups: dict[tuple, list] = defaultdict(list)
    for s in runs:
        groups[(s["target"], level_of(s["run_id"]), s["tool"])].append(s)

    print(f"{'target':<30}{'lvl':<11}{'tool':<20}{'runs':>5}{'detect':>12}{'confirm':>12}{'FP':>7}{'cost$':>9}")
    print("-" * 104)
    for (target, level, tool), ss in sorted(groups.items()):
        n = len(ss)
        ninst = len(ss[0]["instances"])
        det = [sum(1 for iv in s["instances"] if iv["detected"]) for s in ss]
        conf = [sum(1 for iv in s["instances"] if iv["exploited"]) for s in ss]
        fp = [s["false_positives"] for s in ss]
        cost = sum(s["cost_usd"] for s in ss)
        dm, dsd = _mean_sd(det); cm, csd = _mean_sd(conf); fpm, _ = _mean_sd(fp)
        print(f"{target:<30}{level:<11}{tool:<20}{n:>5}"
              f"{f'{dm:.1f}/{ninst}':>12}{f'{cm:.1f}/{ninst}':>12}{fpm:>7.1f}{cost:>9.2f}")

    # per-class exploit-success + pass@k across runs, for the vulnerable instances
    print("\nPer-class exploit-success (confirmed across runs) and pass@k:")
    byclass: dict[tuple, list] = defaultdict(list)   # (target,tool,class,label_id) -> [exploited bools]
    vulnerable: dict[tuple, bool] = {}
    for s in runs:
        for iv in s["instances"]:
            if iv["is_vulnerable"]:
                k = (s["target"], s["tool"], iv["vuln_class"], iv["label_id"])
                byclass[k].append(bool(iv["exploited"]))
    agg: dict[tuple, list] = defaultdict(list)        # (target,tool,class) -> per-instance confirm-rates
    passk: dict[tuple, list] = defaultdict(list)
    for (tgt, tool, cls, lid), evs in byclass.items():
        agg[(tgt, tool, cls)].append(sum(evs) / len(evs))
        passk[(tgt, tool, cls)].append(1 if any(evs) else 0)
    for (tgt, tool, cls), rates in sorted(agg.items()):
        pk = passk[(tgt, tool, cls)]
        print(f"  {tgt:<28} {tool:<18} {cls:<18} exploit-success={st.mean(rates):.2f}  "
              f"pass@k={sum(pk)}/{len(pk)} instances")

    total = sum(s["cost_usd"] for s in runs)
    confirmed = sum(sum(1 for iv in s["instances"] if iv["exploited"]) for s in runs)
    print(f"\nTOTAL: {len(runs)} runs, ${total:.2f}, {confirmed} confirmed exploits"
          f"{f', ${total/confirmed:.3f}/confirmed' if confirmed else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
