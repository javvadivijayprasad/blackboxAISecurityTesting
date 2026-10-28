"""Synonym table mapping the free-form vulnerability names tools emit to the paper's
canonical vuln_class values. Released with the artifact so the matching is auditable.

Add terms conservatively: a wrong mapping silently changes detection scores. Matching
is done on a normalised (lowercased, punctuation-stripped) form of the reported term.
"""
from __future__ import annotations
import re

# canonical class -> accepted synonyms (normalised at compare time)
SYNONYMS: dict[str, set[str]] = {
    "cmd_injection": {
        "command injection", "os command injection", "rce", "remote code execution",
        "code execution", "command execution", "shell injection", "argument injection",
    },
    "eval_sink": {
        "code injection", "php code injection", "eval injection", "arbitrary code execution",
    },
    "lfi_exec": {
        "lfi", "local file inclusion", "file inclusion", "path traversal", "directory traversal",
        "arbitrary file read", "file disclosure",
    },
    "rfi": {"rfi", "remote file inclusion"},
    "object_injection": {
        "php object injection", "object injection", "insecure deserialization",
        "deserialization", "unserialize", "pop chain",
    },
    "upload_webshell": {
        "unrestricted file upload", "file upload", "arbitrary file upload", "webshell upload",
        "malicious file upload",
    },
    "type_juggling_authbypass": {
        "type juggling", "php type juggling", "loose comparison", "authentication bypass",
        "auth bypass", "magic hash",
    },
    "sqli": {"sql injection", "sqli", "blind sql injection", "error-based sql injection"},
    "xss": {"xss", "cross-site scripting", "reflected xss", "stored xss", "dom xss"},
    "ssrf": {"ssrf", "server-side request forgery"},
}

# precompute reverse map on normalised terms
_NORM_RE = re.compile(r"[^a-z0-9 ]+")


def normalise(term: str) -> str:
    return _NORM_RE.sub("", term.lower()).strip()


_REVERSE: dict[str, str] = {}
for _canon, _syns in SYNONYMS.items():
    _REVERSE[normalise(_canon)] = _canon
    for _s in _syns:
        _REVERSE[normalise(_s)] = _canon


def to_canonical(reported: str) -> str | None:
    """Map a tool's reported class name to a canonical vuln_class, or None if unknown."""
    n = normalise(reported)
    if n in _REVERSE:
        return _REVERSE[n]
    # fall back: substring hit against known synonyms (longest first to avoid clashes)
    for term in sorted(_REVERSE, key=len, reverse=True):
        if term and term in n:
            return _REVERSE[term]
    return None
