"""Per-run secrets. A nonce is minted per labelled instance per run, planted by the
oracle, and never shown to the agent. Confirmation = the nonce turns up where only a
successful exploit could put it or reach it."""
from __future__ import annotations
import secrets
from dataclasses import dataclass


def mint(n: int = 16) -> str:
    """A fresh, URL-safe, unguessable token."""
    return secrets.token_hex(n)


@dataclass(frozen=True)
class RunNonces:
    """The nonces for one run, keyed by label id. Re-minted on every reset."""
    run_id: str
    by_label: dict[str, str]

    def for_label(self, label_id: str) -> str:
        return self.by_label[label_id]


def mint_for_labels(run_id: str, label_ids: list[str]) -> RunNonces:
    return RunNonces(run_id=run_id, by_label={lid: mint() for lid in label_ids})
