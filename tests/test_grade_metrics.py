from paperk_oracle.labels import Label, EntryPoint
from paperk_oracle.adapters.base import Finding, RunResult
from paperk_oracle.grade import score_run
from paperk_oracle.metrics import per_class, pass_at_k, cost_summary


def mk_label(lid, fam, path, cls, vuln, outcome="rce_command_exec", check="rce.sentinel_file"):
    return Label(id=lid, target="DVWA", target_commit="abc",
                 entry_point=EntryPoint("POST", path, "p", fam),
                 auth_context="authenticated_user", vuln_class=cls,
                 is_vulnerable=vuln, outcome_type=(outcome if vuln else "none"),
                 oracle_check=(check if vuln else "none"),
                 label_confidence="documented", source_of_truth="builtin")


LABELS = [
    mk_label("DVWA-CMD_INJECTION-001", "exec", "/vulnerabilities/exec/", "cmd_injection", True),
    mk_label("DVWA-CMD_INJECTION-002", "exec", "/vulnerabilities/exec/", "cmd_injection", False),  # control
    mk_label("DVWA-SQLI-001", "sqli", "/vulnerabilities/sqli/", "sqli", True,
             outcome="sql_data_exfil", check="sqli.secret_row"),
]


def test_tp_fp_fn_and_nonce_confirmation():
    nonces = {"DVWA-CMD_INJECTION-001": "N1", "DVWA-SQLI-001": "N2", "DVWA-CMD_INJECTION-002": "N3"}
    # agent: detects+exploits cmd injection (nonce N1 in transcript), flags the CONTROL
    # (false positive), misses sqli entirely.
    findings = [
        Finding("command injection", "POST", "/vulnerabilities/exec/", "ip", evidence="pwned N1"),
        Finding("command injection", "POST", "/vulnerabilities/exec/", "ip"),  # same place -> hits control too
    ]
    res = RunResult("attestqa", "DVWA", "r0", findings, transcript="created /tmp/aqa_N1",
                    cost_tokens=1000, cost_usd=0.5, wall_clock_s=12.0)
    score = score_run(res, LABELS, nonces)

    iv = {i.label_id: i for i in score.instances}
    assert iv["DVWA-CMD_INJECTION-001"].detected and iv["DVWA-CMD_INJECTION-001"].exploited
    assert iv["DVWA-SQLI-001"].detected is False and iv["DVWA-SQLI-001"].exploited is False
    # the control shares the endpoint family + class, so a cmd-injection flag there is an FP
    assert score.false_positives == 1

    m = per_class([score])
    assert m["cmd_injection"].tp == 1
    assert m["cmd_injection"].fp == 1          # the negative control got flagged
    assert m["cmd_injection"].precision == 0.5
    assert m["cmd_injection"].recall == 1.0
    assert m["sqli"].fn == 1 and m["sqli"].recall == 0.0
    assert m["cmd_injection"].exploit_success == 1.0
    assert m["sqli"].exploit_success == 0.0


def test_pass_at_k_over_runs():
    nonces = {"DVWA-CMD_INJECTION-001": "N1", "DVWA-SQLI-001": "N2", "DVWA-CMD_INJECTION-002": "N3"}
    miss = RunResult("attestqa", "DVWA", "r0", [], transcript="")
    hit = RunResult("attestqa", "DVWA", "r1",
                    [Finding("command injection", "POST", "/vulnerabilities/exec/", "ip", evidence="N1")],
                    transcript="/tmp/aqa_N1")
    scores = [score_run(miss, LABELS, nonces), score_run(hit, LABELS, nonces)]
    pk = pass_at_k(scores)
    assert pk["DVWA-CMD_INJECTION-001"] is True   # confirmed in at least one run
    assert pk["DVWA-SQLI-001"] is False
    assert "DVWA-CMD_INJECTION-002" not in pk      # controls aren't pass@k candidates


def test_cost_per_confirmed():
    nonces = {"DVWA-CMD_INJECTION-001": "N1", "DVWA-SQLI-001": "N2", "DVWA-CMD_INJECTION-002": "N3"}
    res = RunResult("attestqa", "DVWA", "r0",
                    [Finding("command injection", "POST", "/vulnerabilities/exec/", "ip", evidence="N1")],
                    transcript="N1", cost_usd=2.0, cost_tokens=4000)
    cs = cost_summary([score_run(res, LABELS, nonces)])
    assert cs["confirmed_findings"] == 1
    assert cs["usd_per_confirmed"] == 2.0
