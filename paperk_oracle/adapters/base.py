"""Common types for anything that produces findings: the agent under test and the
scanner baselines. They all emit the same Finding shape so the grader treats them
identically (a like-for-like comparison is the point of RQ3)."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Finding:
    """One reported vulnerability from any tool. `evidence` is the free text / captured
    response the tool offers as proof — the oracle scans it for the planted nonce."""
    reported_class: str          # tool's own words; mapped via synonyms.to_canonical
    method: str
    path: str
    param: str | None = None
    evidence: str = ""           # may contain the nonce if the exploit truly succeeded
    raw: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RunResult:
    """Everything one tool produced on one target in one run."""
    tool: str
    target: str
    run_id: str
    findings: list[Finding]
    cost_tokens: int = 0
    cost_usd: float = 0.0
    wall_clock_s: float = 0.0
    transcript: str = ""         # full agent transcript, also scanned for nonces


class Tool(Protocol):
    """Adapter interface. Implementations get black-box access only: base_url + creds."""
    name: str

    def run(self, *, target: str, base_url: str, creds: dict | None, run_id: str) -> RunResult:
        ...
