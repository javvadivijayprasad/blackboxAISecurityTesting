"""OWASP ZAP baseline adapter — the free control the paper contrasts with the agent.

Drives a running ZAP daemon via the ZAP API: (optional) authenticated-session setup,
traditional spider, active scan, then maps every ZAP alert to a common Finding. The ZAP
alert name becomes Finding.reported_class (synonyms.to_canonical maps it to a vuln_class);
the alert URL/param carry location; attack+evidence+otherinfo become Finding.evidence.

By design a scanner never learns the planted per-run nonce, so exploit-success comes out
~0 — that gap vs the agent is a result (design s2), not a bug. If ZAP ever shows exploit>0,
the oracle is leaking the nonce and must be fixed before anything downstream is trusted.

The adapter is target-agnostic. Target specifics (DVWA login + security level) are supplied
via `session_setup`, which issues its requests THROUGH the ZAP proxy so ZAP keeps the
authenticated session for the spider/scan. See targets_config.dvwa_zap_session_setup.
"""
from __future__ import annotations
import time
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from .base import Finding, RunResult

# session_setup(zap, proxies, scan_url, creds) -> None : establish an authenticated session.
# Receives the live ZAPv2 client so it can pin the session into ZAP (e.g. a Replacer rule)
# and the proxies dict so it can drive the login through ZAP.
SessionSetup = Callable[["object", dict, str, "dict | None"], None]

_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class ZapAdapter:
    name = "owasp-zap"

    def __init__(self, zap_api: str = "http://127.0.0.1:8090", api_key: str | None = None, *,
                 scan_host: str | None = None, session_setup: SessionSetup | None = None,
                 seed_requests: "list[dict] | None" = None,
                 exclude_paths: "list[str] | None" = None,
                 spider_timeout_min: int = 5, ascan_timeout_min: int = 20, poll_s: float = 3.0):
        self.zap_api = zap_api
        self.api_key = api_key
        self.scan_host = scan_host            # host:port ZAP uses to reach the target; None -> auto
        self.session_setup = session_setup
        # Parameterised requests to prime into ZAP's tree before the active scan, so the
        # scanner attacks params the traditional spider won't submit (POST forms, etc.). Each:
        # {"method": "GET"|"POST", "path": "/...", "params": {...}} or {"data": {...}}.
        self.seed_requests = seed_requests or []
        # Regexes (full-URL) to keep OUT of spider + active scan. Critical for session-based
        # targets: scanning /logout.php destroys the pinned session and the rest of the scan
        # runs unauthenticated; scanning /security.php or /setup.php can flip the build.
        self.exclude_paths = exclude_paths or []
        self.spider_timeout_min = spider_timeout_min
        self.ascan_timeout_min = ascan_timeout_min
        self.poll_s = poll_s

    def _scan_url(self, base_url: str) -> str:
        """URL ZAP (in its own container) should fetch. Loopback on the host is not reachable
        from inside the ZAP container, so rewrite it to host.docker.internal unless the caller
        pinned an explicit scan_host."""
        parts = urlsplit(base_url)
        if self.scan_host:
            netloc = self.scan_host
        elif (parts.hostname or "") in _LOOPBACK:
            netloc = f"host.docker.internal:{parts.port}" if parts.port else "host.docker.internal"
        else:
            netloc = parts.netloc
        return urlunsplit((parts.scheme, netloc, parts.path or "/", "", ""))

    def run(self, *, target: str, base_url: str, creds: dict | None, run_id: str) -> RunResult:
        from zapv2 import ZAPv2   # lazy: the deterministic core and its tests don't need zaproxy
        t0 = time.time()
        scan_url = self._scan_url(base_url)
        proxies = {"http": self.zap_api, "https": self.zap_api}
        zap = ZAPv2(apikey=self.api_key, proxies=proxies)

        # fresh session so state never leaks across runs (design s4)
        zap.core.new_session(name=run_id, overwrite=True)

        # keep session-breaking / build-flipping endpoints out of spider + active scan
        for pat in self.exclude_paths:
            for mod in (zap.spider, zap.ascan):
                try:
                    mod.exclude_from_scan(pat)
                except Exception:
                    pass

        # optional authenticated-session / security-level setup (pins the session into ZAP)
        if self.session_setup:
            self.session_setup(zap, proxies, scan_url, creds)

        # seed the tree, spider, then active-scan
        zap.urlopen(scan_url)
        time.sleep(1)
        self._seed(proxies, scan_url)
        sid = zap.spider.scan(scan_url)
        self._await(lambda: int(zap.spider.status(sid)), self.spider_timeout_min)

        aid = zap.ascan.scan(scan_url)
        self._await(lambda: int(zap.ascan.status(aid)), self.ascan_timeout_min)

        findings = self._collect(zap, scan_url)
        transcript = (f"ZAP {run_id}: scanned {scan_url}; spider+active scan complete; "
                      f"{len(findings)} alert(s).")
        return RunResult(self.name, target, run_id, findings,
                         wall_clock_s=time.time() - t0, transcript=transcript)

    def _seed(self, proxies: dict, scan_url: str) -> None:
        """Send each seed request THROUGH ZAP so its parameterised node enters the tree and
        the active scan will attack it. Routed via the proxy so any session_setup auth
        (e.g. a Replacer cookie rule) applies."""
        if not self.seed_requests:
            return
        import requests
        from urllib.parse import urljoin
        s = requests.Session(); s.proxies.update(proxies); s.verify = False
        for seed in self.seed_requests:
            url = urljoin(scan_url, seed["path"])
            try:
                if seed.get("method", "GET").upper() == "POST":
                    s.post(url, data=seed.get("data", seed.get("params", {})), timeout=30)
                else:
                    s.get(url, params=seed.get("params", {}), timeout=30)
            except Exception:
                pass  # seeding is best-effort; a failed seed just means that node isn't primed

    def _await(self, status_fn: Callable[[], int], timeout_min: int) -> None:
        """Poll a ZAP 0-100 progress endpoint until done or timed out."""
        deadline = time.time() + timeout_min * 60
        while True:
            try:
                if status_fn() >= 100:
                    return
            except Exception:
                pass  # ZAP occasionally 404s a status mid-start; retry until the deadline
            if time.time() > deadline:
                return
            time.sleep(self.poll_s)

    def _collect(self, zap, scan_url: str) -> list[Finding]:
        findings: list[Finding] = []
        for a in zap.core.alerts(baseurl=scan_url):
            evidence = " | ".join(x for x in (a.get("attack", ""), a.get("evidence", ""),
                                              a.get("otherinfo", "")) if x)
            findings.append(Finding(
                reported_class=a.get("alert") or a.get("name", ""),
                method=a.get("method", "GET"),
                path=a.get("url", ""),
                param=a.get("param") or None,
                evidence=evidence,
                raw=a,
            ))
        return findings
