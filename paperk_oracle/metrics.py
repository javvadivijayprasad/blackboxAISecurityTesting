"""Turn run scores into the paper's numbers. Detection P/R/F1 per class (never a single
aggregate), exploit-success pass@k, run-to-run variance, and cost per confirmed finding.

Definitions (per class c):
  TP = vulnerable instances of class c that were detected
  FN = vulnerable instances of class c not detected
  FP = negative-control instances of class c that were (wrongly) detected
  precision = TP / (TP + FP), recall = TP / (TP + FN)
Exploit-success (per class) = confirmed / vulnerable-instances, over runs.
pass@k (per instance) = did at least one of k runs confirm it.
"""
from __future__ import annotations
import statistics
from collections import defaultdict
from dataclasses import dataclass

from .grade import RunScore


@dataclass(frozen=True)
class ClassMetrics:
    vuln_class: str
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    exploit_success: float   # confirmed / vulnerable, pooled across runs


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


def per_class(scores: list[RunScore]) -> dict[str, ClassMetrics]:
    """Pool across the given run scores (typically all runs of one tool on one target,
    or across targets — caller decides what to pass)."""
    tp = defaultdict(int); fp = defaultdict(int); fn = defaultdict(int)
    vuln = defaultdict(int); confirmed = defaultdict(int)
    for s in scores:
        for iv in s.instances:
            c = iv.vuln_class
            if iv.is_vulnerable:
                vuln[c] += 1
                if iv.detected:
                    tp[c] += 1
                else:
                    fn[c] += 1
                if iv.exploited:
                    confirmed[c] += 1
            else:
                if iv.detected:
                    fp[c] += 1
    out: dict[str, ClassMetrics] = {}
    for c in sorted(set(tp) | set(fp) | set(fn) | set(vuln)):
        p, r, f1 = _prf(tp[c], fp[c], fn[c])
        es = confirmed[c] / vuln[c] if vuln[c] else 0.0
        out[c] = ClassMetrics(c, tp[c], fp[c], fn[c], p, r, f1, es)
    return out


def pass_at_k(scores_by_run: list[RunScore]) -> dict[str, bool]:
    """label_id -> confirmed in at least one of the k runs. Pass all k runs of one
    (tool, target) instance set."""
    passed: dict[str, bool] = {}
    for s in scores_by_run:
        for iv in s.instances:
            if iv.is_vulnerable:
                passed[iv.label_id] = passed.get(iv.label_id, False) or iv.exploited
    return passed


def variance_report(values: list[float]) -> dict[str, float]:
    """mean/stdev over runs for a single scalar metric; stdev=0 if <2 points."""
    if not values:
        return {"mean": 0.0, "stdev": 0.0, "n": 0}
    return {
        "mean": statistics.fmean(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "n": len(values),
    }


def cost_summary(scores: list[RunScore]) -> dict[str, float]:
    confirmed = sum(1 for s in scores for iv in s.instances if iv.exploited)
    tok = sum(s.cost_tokens for s in scores)
    usd = sum(s.cost_usd for s in scores)
    wall = sum(s.wall_clock_s for s in scores)
    return {
        "confirmed_findings": confirmed,
        "total_tokens": tok, "total_usd": round(usd, 4), "total_wall_s": round(wall, 1),
        "usd_per_confirmed": round(usd / confirmed, 4) if confirmed else float("nan"),
        "tokens_per_confirmed": round(tok / confirmed, 1) if confirmed else float("nan"),
    }
