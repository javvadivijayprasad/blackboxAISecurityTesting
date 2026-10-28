"""First agent run — Claude black-box tester against DVWA (runbook step 7).

Usage (ANTHROPIC_API_KEY must be set in the environment):
    set PYTHONPATH=.
    python run_agent.py low          # Run A (vulnerable build)
    python run_agent.py impossible   # Run B (control build)

Separate runs per level (design s6). Uses 127.0.0.1 (dotted host) so the authenticated
session's security cookie is sent reliably. The agent gets only base_url + creds (+ callback
when wired); the session_provider pins the deployment level without telling the agent.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

from paperk_oracle.labels import load
from paperk_oracle.runner import TargetSpec, run_once, save_scores
from paperk_oracle.adapters.attestqa import AttestqaAdapter
from targets_config import DVWA, dvwa_agent_session, dvwa_reinit, DVWA_ZAP_EXCLUDE

BASE_URL = "http://127.0.0.1:4280"
COMPOSE_DIR = r"..\targets\DVWA"


def _resolve_api_key() -> str | None:
    """Prefer ANTHROPIC_API_KEY from the env; else read a local .anthropic_key file
    (one line, just the key) next to this script. The key is never printed."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return None  # let the SDK read the env var itself
    f = Path(__file__).with_name(".anthropic_key")
    if f.exists():
        return f.read_text(encoding="utf-8").strip() or None
    raise SystemExit("No API key: set ANTHROPIC_API_KEY (then reload the window) "
                     "or save the key to .anthropic_key next to run_agent.py")


def _resolve_workspace_id() -> str | None:
    """Optional: a workspace id for org-level (non-workspace-scoped) keys. Not a secret."""
    if os.environ.get("ANTHROPIC_WORKSPACE_ID"):
        return os.environ["ANTHROPIC_WORKSPACE_ID"]
    f = Path(__file__).with_name(".anthropic_workspace")
    return f.read_text(encoding="utf-8").strip() if f.exists() else None


def main(level: str = "low", repeats: int = 1) -> int:
    if level not in ("low", "medium", "high", "impossible"):
        print(f"unknown level {level!r}"); return 2

    labels = load(f"labels/DVWA.{level}.labels.yaml")
    # post_reset_init wired so reset=True re-creates DVWA's schema between trials (design s4).
    spec = TargetSpec(key="DVWA", base_url=BASE_URL, compose_dir=COMPOSE_DIR,
                      plant_cfg=DVWA, creds={"user": "admin", "pass": "password"},
                      post_reset_init=dvwa_reinit)
    tool = AttestqaAdapter(provider="claude", api_key=_resolve_api_key(),
                           workspace_id=_resolve_workspace_id(),
                           session_provider=dvwa_agent_session(level),
                           exclude_paths=DVWA_ZAP_EXCLUDE,
                           max_iterations=30, effort="medium")

    # Single run: no reset (fast, on the live container). Repeats: reset=True so each trial
    # starts clean — the precondition for a trustworthy pass@k.
    reset = repeats > 1
    scores = []
    for i in range(repeats):
        rid = f"DVWA-{level}-attestqa-claude-r{i}"
        s = run_once(tool, spec, labels, run_id=rid, use_docker=True, reset=reset, artifacts_dir=".")
        scores.append(s)
        print(f"  {rid}: detect {sum(1 for iv in s.instances if iv.detected)}/4, "
              f"confirm {sum(1 for iv in s.instances if iv.exploited)}/4, FP {s.false_positives}, "
              f"${s.cost_usd} / {round(s.wall_clock_s)}s")

    out = f"scores.DVWA.{level}.attestqa{'.x'+str(repeats) if repeats > 1 else ''}.json"
    save_scores(scores, out)
    total = sum(s.cost_usd for s in scores)
    print(f"saved {out}: {len(scores)} run(s); total cost ${round(total, 4)} / "
          f"{sum(s.cost_tokens for s in scores)} tok")
    return 0


if __name__ == "__main__":
    lvl = sys.argv[1] if len(sys.argv) > 1 else "low"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    raise SystemExit(main(lvl, n))
