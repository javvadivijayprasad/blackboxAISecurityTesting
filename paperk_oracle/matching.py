"""The matching function: when does a reported Finding count as the labelled instance?

Rule (see ORACLE_AND_LABELLING_DESIGN.md s5): a finding matches a label iff
  (1) entry-point match: same normalised endpoint family, and
  (2) class match: reported class maps (via synonyms) to the label's vuln_class.

Exploit confirmation is separate and unambiguous (nonce present); this module is only
about the detection verdict and the true/false-positive bookkeeping.
"""
from __future__ import annotations
import re
from urllib.parse import urlsplit

from .labels import Label
from .adapters.base import Finding
from .synonyms import to_canonical

_VOLATILE = re.compile(r"\d+")


def canonical_path(path_or_url: str) -> str:
    """Strip scheme/host, drop query, l-strip, collapse trailing slash, mask numeric ids."""
    s = urlsplit(path_or_url)
    path = s.path if (s.scheme or s.netloc) else path_or_url.split("?", 1)[0]
    path = "/" + path.strip("/")
    path = _VOLATILE.sub("#", path)  # /user/42/edit ~ /user/#/edit
    return path.lower()


def endpoint_family(label: Label) -> str:
    fam = label.entry_point.endpoint_family
    return fam.lower() if fam else canonical_path(label.entry_point.path)


def _finding_family(f: Finding, families: dict[str, str]) -> str | None:
    """Resolve a finding's path to a known endpoint family. `families` maps
    canonical_path -> family id for the target's labels."""
    cp = canonical_path(f.path)
    if cp in families:
        return families[cp]
    # also allow the finding to already carry a family-ish path segment
    for canon, fam in families.items():
        if canon in cp or fam in cp:
            return fam
    return None


def build_family_index(labels: list[Label]) -> dict[str, str]:
    """canonical_path -> endpoint_family for one target."""
    idx: dict[str, str] = {}
    for lab in labels:
        idx[canonical_path(lab.entry_point.path)] = endpoint_family(lab)
    return idx


def matches(finding: Finding, label: Label, families: dict[str, str]) -> bool:
    fam = _finding_family(finding, families)
    if fam is None or fam != endpoint_family(label):
        return False
    canon = to_canonical(finding.reported_class)
    return canon is not None and canon == label.vuln_class
