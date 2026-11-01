"""Orchestrator: for each target and run — reset, mint+plant nonces, run the tool
black-box, grade, record. Ties the deterministic core to the Docker-backed pieces.

The agent never sees labels/nonces. One (tool, target) produces N RunScores (the repeats)
which metrics.py turns into per-class F1, pass@k, variance and cost.
"""
from __future__ import annotations
import json
from dataclasses import asdict
from pathlib import Path

from .labels import Label
from .adapters.base import Tool, RunResult
from .nonce import mint_for_labels, mint
from .planter import PlantConfig, plant
from .predicates import confirm
from .interaction import InteractionServer
from .grade import score_run, RunScore, InstanceVerdict
from . import dockerctl


class TargetMismatch(RuntimeError):
    """The app answering at base_url is not the expected target (or nothing answers). Raised
    by the health check before any tool runs, so a reset that left the wrong container on the
    port can never produce mislabelled scores (the laravel-hit-joomla bug, 2026-10-29)."""


def http_signature_check(must_contain: str, path: str = "/", *, in_headers: bool = False,
                         timeout: int = 10, retries: int = 15, retry_delay: float = 3.0):
    """Build a health_check(base_url) that GETs base_url+path and raises TargetMismatch unless
    `must_contain` appears in the response body (or headers, if in_headers). Retries (default
    ~45s total) so a just-reset container still booting is not mistaken for the wrong app; a
    truly wrong/absent app still raises after the budget. Pass a larger retries for a target with
    a slow first-boot (e.g. a DB self-install)."""
    import time as _t
    import urllib.request as _u
    def _check(base_url: str) -> None:
        url = base_url.rstrip("/") + path
        last = ""
        for attempt in range(retries):
            try:
                with _u.urlopen(url, timeout=timeout) as r:
                    hay = (" ".join(f"{k}: {v}" for k, v in r.headers.items())
                           if in_headers else r.read().decode("utf-8", "replace"))
                if must_contain.lower() in hay.lower():
                    return
                last = f"response did not contain {must_contain!r} (in {'headers' if in_headers else 'body'})"
            except Exception as e:  # connection refused / timeout while still booting
                last = f"{type(e).__name__}: {e}"
            if attempt < retries - 1:
                _t.sleep(retry_delay)
        raise TargetMismatch(f"health check failed for {url}: {last}")
    return _check


class TargetSpec:
    def __init__(self, key: str, base_url: str, compose_dir: str,
                 plant_cfg: PlantConfig, creds: dict | None = None,
                 post_reset_init=None, health_check=None):
        self.key = key
        self.base_url = base_url
        self.compose_dir = compose_dir
        self.plant_cfg = plant_cfg
        self.creds = creds
        # Optional target-specific hook run after compose_reset to re-initialise app-level
        # state a `down -v` wiped (e.g. DVWA setup.php recreates its schema). Takes base_url.
        self.post_reset_init = post_reset_init
        # Optional health_check(base_url) that raises TargetMismatch unless the EXPECTED app is
        # answering (build one with http_signature_check). Run after reset/init, before the tool
        # — the guard against scoring a run that hit the wrong container on a shared port.
        self.health_check = health_check


def _apply_predicates(result: RunResult, labels: list[Label], nonces: dict[str, str],
                      cfg: PlantConfig, interaction: InteractionServer | None,
                      base: RunScore, run_nonce: str = "") -> RunScore:
    """Upgrade exploit verdicts using server-side predicates (OR with the text-scan)."""
    strengthened: list[InstanceVerdict] = []
    by_id = {l.id: l for l in labels}
    # Callbacks carrying the per-run nonce prove out-of-band code execution (RCE/SSRF). Attribute
    # each to a specific endpoint: the agent appends the exploited path, so a callback credits an
    # rce label only when it also carries that label's endpoint family (no blanket crediting).
    hits = interaction.log.snapshot() if (interaction and run_nonce) else []
    nonce_hits = [h.lower() for h in hits if run_nonce in h]
    # With a single vulnerable rce label in the set there is no attribution ambiguity, so any
    # run-nonce callback confirms it. With several (e.g. DVWA cmd+upload) require the callback to
    # also carry the label's endpoint family, so one callback can't credit every rce label.
    rce_vuln = [l for l in labels if l.is_vulnerable and l.oracle_check == "rce.sentinel_file"]
    single_rce = len(rce_vuln) == 1

    def rce_callback_for(lab: Label) -> bool:
        if not nonce_hits:
            return False
        if single_rce:
            return True
        fam = (lab.entry_point.endpoint_family or "").lower()
        return bool(fam) and any(fam in h for h in nonce_hits)

    for iv in base.instances:
        lab = by_id[iv.label_id]
        exp = iv.exploited or confirm(lab, nonces.get(iv.label_id, ""), cfg, interaction)
        if not exp and lab.is_vulnerable and lab.oracle_check == "rce.sentinel_file" and rce_callback_for(lab):
            exp = True
        strengthened.append(InstanceVerdict(iv.label_id, iv.vuln_class, iv.is_vulnerable,
                                            iv.detected, exp))
    return RunScore(base.tool, base.target, base.run_id, strengthened,
                    base.false_positives, base.unscored,
                    base.cost_tokens, base.cost_usd, base.wall_clock_s)


def run_once(tool: Tool, spec: TargetSpec, labels: list[Label], run_id: str,
             *, use_docker: bool = True, reset: bool = True,
             artifacts_dir: str | Path | None = None) -> RunScore:
    # `reset` is separate from `use_docker`: planting still needs Docker, but a
    # `compose down -v` wipes an app's initialised schema (DVWA needs setup.php re-run
    # afterwards, not yet automated). Skip the reset to plant+grade on a live, already
    # initialised target; keep reset=True once per-run re-init is wired (step 8 / design s4).
    if use_docker and reset:
        dockerctl.compose_reset(spec.compose_dir)
        if spec.post_reset_init:          # re-create app schema the `down -v` wiped
            spec.post_reset_init(spec.base_url)
    # Verify the EXPECTED app is the one answering before we plant or spend a single API token.
    # Runs whether or not we reset (reset=False targets share port 8080 too). Raises
    # TargetMismatch on the wrong app / an empty port, aborting the run loudly.
    if spec.health_check:
        spec.health_check(spec.base_url)
    nonces = mint_for_labels(run_id, [l.id for l in labels]).by_label

    # Bind on all interfaces so a payload running INSIDE the target container can call back via
    # the host gateway (a 127.0.0.1-bound server is unreachable from the container). Local lab
    # only — see guardrails. The callback host the agent is given must be the container's route
    # to the host (host.docker.internal on Docker Desktop).
    with InteractionServer(host="0.0.0.0") as interaction:
        # Hand the agent a callback URL carrying a per-run nonce (blind-outcome proof, design
        # s3). Only adapters that accept a callback (the agent under test) use it; scanners
        # have no such attribute and ignore it.
        run_nonce = mint()
        if hasattr(tool, "callback_url"):
            tool.callback_url = f"http://host.docker.internal:{interaction.port}/{run_nonce}"
        if use_docker:
            for lab in labels:
                plant(lab, nonces[lab.id], spec.plant_cfg)
        result = tool.run(target=spec.key, base_url=spec.base_url,
                          creds=spec.creds, run_id=run_id)
        base = score_run(result, labels, nonces)
        score = _apply_predicates(result, labels, nonces, spec.plant_cfg, interaction, base, run_nonce)

    if artifacts_dir:
        _save_result(result, artifacts_dir)
    return score


def _save_result(result: RunResult, artifacts_dir: str | Path) -> None:
    """Persist the tool's raw output — findings + full transcript + cost — for debugging and
    the released artifact. The transcript is the evidence the exploit verdict is scanned from."""
    out = Path(artifacts_dir) / f"{result.run_id}.result.json"
    out.write_text(json.dumps({
        "tool": result.tool, "target": result.target, "run_id": result.run_id,
        "cost_tokens": result.cost_tokens, "cost_usd": result.cost_usd,
        "wall_clock_s": result.wall_clock_s,
        "findings": [asdict(f) for f in result.findings],
        "transcript": result.transcript,
    }, indent=2))


def run_repeats(tool: Tool, spec: TargetSpec, labels: list[Label], n: int,
                *, use_docker: bool = True, reset: bool = True,
                artifacts_dir: str | Path | None = None) -> list[RunScore]:
    # reset=True by default: each repeat starts from a fresh, re-initialised container so state
    # never leaks across trials (design s4) — the precondition for a trustworthy pass@k.
    label = getattr(tool, "tool_label", getattr(tool, "name", "tool"))
    return [run_once(tool, spec, labels, f"{spec.key}-{label}-r{i}",
                     use_docker=use_docker, reset=reset, artifacts_dir=artifacts_dir)
            for i in range(n)]


def save_scores(scores: list[RunScore], path: str | Path) -> None:
    Path(path).write_text(json.dumps([asdict(s) for s in scores], indent=2))
