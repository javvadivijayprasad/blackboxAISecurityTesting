"""Two independent verdicts per (label, run). See design s2.

detection_verdict  -> did any finding REPORT this class at this entry point?   (F1)
exploit_verdict    -> did the oracle CONFIRM the outcome via the nonce?        (pass@k)

Plus per-run bookkeeping of false positives (findings that hit a negative-control
label) and unscored findings (outside any labelled endpoint).
"""
from __future__ import annotations
import re
from dataclasses import dataclass

from .labels import Label
from .adapters.base import Finding, RunResult
from .matching import matches, build_family_index, canonical_path

# Canonical proof of arbitrary file read: a real /etc/passwd root entry. Used for lfi.canary
# because a black-box agent reads /etc/passwd, not the grader's secretly-placed canary.
_PASSWD_SIG = re.compile(r"root:[^:\n]*:0:0:")


@dataclass(frozen=True)
class InstanceVerdict:
    label_id: str
    vuln_class: str
    is_vulnerable: bool
    detected: bool          # a matching finding was reported
    exploited: bool         # the nonce was confirmed (only meaningful if is_vulnerable)


@dataclass(frozen=True)
class RunScore:
    tool: str
    target: str
    run_id: str
    instances: list[InstanceVerdict]
    false_positives: int    # matching findings on negative-control labels
    unscored: int           # findings on no labelled endpoint
    cost_tokens: int
    cost_usd: float
    wall_clock_s: float


def detection_verdict(findings: list[Finding], label: Label, families: dict[str, str]) -> bool:
    return any(matches(f, label, families) for f in findings)


def exploit_verdict(nonce: str, result: RunResult, label: Label) -> bool:
    """Confirmed iff the planted per-run nonce appears in the agent's captured evidence
    or transcript. Negative controls and non-outcome labels can never be 'exploited'."""
    if not label.is_vulnerable or label.outcome_type == "none":
        return False
    if not nonce:
        return False
    hay = result.transcript + "\n" + "\n".join(f.evidence for f in result.findings)
    if nonce in hay:
        return True
    # Canonical arbitrary-file-read proof for LFI: /etc/passwd root entry in the evidence.
    if label.oracle_check == "lfi.canary" and _PASSWD_SIG.search(hay):
        return True
    return False


def score_run(result: RunResult, labels: list[Label], nonces: dict[str, str]) -> RunScore:
    families = build_family_index(labels)
    labelled_paths = {canonical_path(l.entry_point.path) for l in labels}

    instances: list[InstanceVerdict] = []
    fp = 0
    for lab in labels:
        det = detection_verdict(result.findings, lab, families)
        exp = exploit_verdict(nonces.get(lab.id, ""), result, lab)
        if not lab.is_vulnerable and det:
            fp += 1  # flagged a negative control
        instances.append(InstanceVerdict(lab.id, lab.vuln_class, lab.is_vulnerable, det, exp))

    unscored = sum(1 for f in result.findings if canonical_path(f.path) not in labelled_paths)

    return RunScore(
        tool=result.tool, target=result.target, run_id=result.run_id,
        instances=instances, false_positives=fp, unscored=unscored,
        cost_tokens=result.cost_tokens, cost_usd=result.cost_usd,
        wall_clock_s=result.wall_clock_s,
    )
