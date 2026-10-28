"""Small CLI: validate labels, and print per-class metrics from saved run scores.
The full run path (reset/plant/agent) needs the live Docker targets on Vijay's PC.

  python -m paperk_oracle.cli validate labels/
  python -m paperk_oracle.cli report scores.json
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

from .labels import load_dir
from .grade import RunScore, InstanceVerdict
from .metrics import per_class, pass_at_k, cost_summary


def _load_scores(path: str) -> list[RunScore]:
    raw = json.loads(Path(path).read_text())
    out = []
    for s in raw:
        insts = [InstanceVerdict(**iv) for iv in s["instances"]]
        out.append(RunScore(s["tool"], s["target"], s["run_id"], insts,
                            s["false_positives"], s["unscored"],
                            s["cost_tokens"], s["cost_usd"], s["wall_clock_s"]))
    return out


def cmd_validate(args: list[str]) -> int:
    labels_dir = args[0] if args else "labels"
    by_target = load_dir(labels_dir, validate=True)
    total = sum(len(v) for v in by_target.values())
    for tgt, labs in by_target.items():
        pos = sum(1 for l in labs if l.is_vulnerable)
        print(f"  {tgt}: {len(labs)} labels ({pos} positive, {len(labs)-pos} control)")
    print(f"OK: {total} labels across {len(by_target)} targets validated")
    return 0


def cmd_report(args: list[str]) -> int:
    if not args:
        print("usage: report <scores.json>"); return 2
    scores = _load_scores(args[0])
    print(f"{'class':<28}{'TP':>4}{'FP':>4}{'FN':>4}{'prec':>7}{'rec':>7}{'F1':>7}{'exploit':>9}")
    for c, m in per_class(scores).items():
        print(f"{c:<28}{m.tp:>4}{m.fp:>4}{m.fn:>4}{m.precision:>7.2f}"
              f"{m.recall:>7.2f}{m.f1:>7.2f}{m.exploit_success:>9.2f}")
    pk = pass_at_k(scores)
    print(f"\npass@k confirmed: {sum(pk.values())}/{len(pk)} vulnerable instances")
    print("cost:", cost_summary(scores))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(__doc__); return 2
    cmd, rest = argv[0], argv[1:]
    return {"validate": cmd_validate, "report": cmd_report}.get(cmd, lambda a: (print("unknown cmd"), 2)[1])(rest)


if __name__ == "__main__":
    raise SystemExit(main())
