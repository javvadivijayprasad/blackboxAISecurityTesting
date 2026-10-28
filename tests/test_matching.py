from paperk_oracle.labels import Label, EntryPoint
from paperk_oracle.adapters.base import Finding
from paperk_oracle.matching import matches, build_family_index, canonical_path
from paperk_oracle.synonyms import to_canonical


def _lab(**kw):
    base = dict(id="T-CMD_INJECTION-001", target="DVWA", target_commit="abc",
                entry_point=EntryPoint("POST", "/vulnerabilities/exec/", "ip", "exec"),
                auth_context="authenticated_user", vuln_class="cmd_injection",
                is_vulnerable=True, outcome_type="rce_command_exec",
                oracle_check="rce.sentinel_file", label_confidence="documented",
                source_of_truth="builtin")
    base.update(kw); return Label(**base)


def test_canonical_path_masks_ids_and_host():
    assert canonical_path("https://x/user/42/edit?z=1") == "/user/#/edit"
    assert canonical_path("/vulnerabilities/exec/") == "/vulnerabilities/exec"


def test_synonym_mapping():
    assert to_canonical("OS Command Injection") == "cmd_injection"
    assert to_canonical("remote code execution") == "cmd_injection"
    assert to_canonical("SQL Injection") == "sqli"
    assert to_canonical("Local File Inclusion") == "lfi_exec"
    assert to_canonical("totally unknown thing") is None


def test_match_requires_both_endpoint_and_class():
    lab = _lab()
    fams = build_family_index([lab])
    hit = Finding("command injection", "POST", "/vulnerabilities/exec/", "ip")
    assert matches(hit, lab, fams)
    # right place, wrong class
    wrong_class = Finding("cross-site scripting", "POST", "/vulnerabilities/exec/", "ip")
    assert not matches(wrong_class, lab, fams)
    # right class, wrong place
    wrong_place = Finding("command injection", "GET", "/vulnerabilities/sqli/", "id")
    assert not matches(wrong_place, lab, fams)
