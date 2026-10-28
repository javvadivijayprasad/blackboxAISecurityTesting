"""Load and validate ground-truth label files against schema/label.schema.json.

Labels are the grader's secret. A label is either a vulnerable instance
(is_vulnerable=True, with an outcome the oracle can confirm) or a negative control
(is_vulnerable=False) used to measure false positives.
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

try:
    import jsonschema
except ImportError:  # validation is optional at import time, required in validate()
    jsonschema = None


@dataclass(frozen=True)
class EntryPoint:
    method: str
    path: str
    param: str | None = None
    endpoint_family: str | None = None

    @property
    def family(self) -> str:
        # fall back to the path if no explicit family was authored
        return self.endpoint_family or self.path


@dataclass(frozen=True)
class Label:
    id: str
    target: str
    target_commit: str
    entry_point: EntryPoint
    auth_context: str
    vuln_class: str
    is_vulnerable: bool
    outcome_type: str
    oracle_check: str
    label_confidence: str
    source_of_truth: str
    difficulty: str = "n/a"
    cwe: str | None = None
    owasp_2021: str | None = None
    control_gaining: bool = False
    image_digest: str | None = None
    notes: str | None = None

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Label":
        ep = d["entry_point"]
        return Label(
            id=d["id"], target=d["target"], target_commit=d["target_commit"],
            entry_point=EntryPoint(ep["method"], ep["path"], ep.get("param"), ep.get("endpoint_family")),
            auth_context=d["auth_context"], vuln_class=d["vuln_class"],
            is_vulnerable=d["is_vulnerable"], outcome_type=d["outcome_type"],
            oracle_check=d["oracle_check"], label_confidence=d["label_confidence"],
            source_of_truth=d["source_of_truth"], difficulty=d.get("difficulty", "n/a"),
            cwe=d.get("cwe"), owasp_2021=d.get("owasp_2021"),
            control_gaining=d.get("control_gaining", False),
            image_digest=d.get("image_digest"), notes=d.get("notes"),
        )


def _schema_path() -> Path:
    return Path(__file__).resolve().parent.parent / "schema" / "label.schema.json"


def validate_raw(entries: list[dict[str, Any]], schema_path: Path | None = None) -> list[str]:
    """Return a list of human-readable errors; empty list means valid."""
    if jsonschema is None:
        raise RuntimeError("jsonschema not installed; `pip install jsonschema`")
    schema = json.loads((schema_path or _schema_path()).read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    v = jsonschema.Draft202012Validator(schema)
    errs: list[str] = []
    seen: set[str] = set()
    for e in entries:
        for err in v.iter_errors(e):
            errs.append(f"{e.get('id', '<no id>')}: {err.message}")
        lid = e.get("id")
        if lid in seen:
            errs.append(f"{lid}: duplicate id")
        seen.add(lid)
    return errs


def load(path: str | Path, *, validate: bool = True) -> list[Label]:
    entries = yaml.safe_load(Path(path).read_text())
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a list of label entries")
    if validate:
        errs = validate_raw(entries)
        if errs:
            raise ValueError("label validation failed:\n  " + "\n  ".join(errs))
    return [Label.from_dict(e) for e in entries]


def load_dir(labels_dir: str | Path, *, validate: bool = True) -> dict[str, list[Label]]:
    """Load every *.labels*.yaml / *.yaml under a directory, keyed by target."""
    out: dict[str, list[Label]] = {}
    for p in sorted(Path(labels_dir).glob("*.y*ml")):
        for lab in load(p, validate=validate):
            out.setdefault(lab.target, []).append(lab)
    return out
