"""Thin wrappers over docker / docker compose for reset, exec, and image digests.
Kept in one place so the Docker dependency is isolated and mockable in tests.

These shell out; they run on the machine hosting the targets (Vijay's PC). Reset gives
each run a fresh container so state never leaks across the N repeats (design s4).
"""
from __future__ import annotations
import subprocess
from pathlib import Path


class DockerError(RuntimeError):
    """A docker/compose command exited non-zero. Raised by _run(check=True) so a failed
    reset (e.g. a port already allocated by a stale target) aborts loudly instead of letting
    the run proceed against the wrong container — the silent-failure trap that mislabelled a
    laravel run as joomla on 2026-10-29."""


def _run(cmd: list[str], cwd: str | Path | None = None, timeout: int = 300,
         check: bool = False) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True,
                       text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise DockerError(
            f"command failed (exit {p.returncode}): {' '.join(cmd)}\n"
            f"cwd={cwd}\n--- stdout ---\n{p.stdout}\n--- stderr ---\n{p.stderr}")
    return p


def compose_up(compose_dir: str | Path) -> None:
    _run(["docker", "compose", "up", "-d", "--build"], cwd=compose_dir, check=True)


def compose_reset(compose_dir: str | Path) -> None:
    """Down with volumes, then up — a clean slate between runs. Recreates containers with a
    FRESH volume but reuses the already-built/pinned image (no --build, no pull) so the reset is
    fast and the image stays fixed across repeats. App-level schema (e.g. DVWA users) is gone
    after this and must be re-initialised by the target's post_reset_init hook.

    check=True on both steps: if `down -v` or `up` fails (a port held by a stale target is the
    usual cause) we raise rather than run the tool against whatever else holds the port."""
    _run(["docker", "compose", "down", "-v"], cwd=compose_dir, check=True)
    _run(["docker", "compose", "up", "-d", "--pull", "never"], cwd=compose_dir, timeout=600, check=True)


def image_digest(image: str) -> str | None:
    p = _run(["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", image])
    out = p.stdout.strip()
    return out or None


def exec_in(container: str, argv: list[str], timeout: int = 60) -> tuple[int, str, str]:
    p = _run(["docker", "exec", container, *argv], timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def file_exists_in(container: str, path: str) -> bool:
    rc, _, _ = exec_in(container, ["test", "-f", path])
    return rc == 0


def write_file_in(container: str, path: str, content: str) -> None:
    # use sh -c with a here-string so we don't depend on a local tempfile
    exec_in(container, ["sh", "-c", f"cat > {path} <<'EOF'\n{content}\nEOF"])


# --- ZAP baseline scanner daemon (adapters/zap.py talks to it over the ZAP API) ----------

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"   # pin by digest for the artifact after first pull


def zap_up(name: str = "paperk-zap", host_port: int = 8090, api_key: str = "paperk") -> None:
    """Start a ZAP daemon container. Published only on loopback; host.docker.internal is
    added so ZAP can reach a target published on the host (Docker Desktop provides it
    automatically, Linux needs the host-gateway alias)."""
    _run(["docker", "rm", "-f", name])  # idempotent: clear any prior daemon
    _run([
        "docker", "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{host_port}:{host_port}",
        "--add-host", "host.docker.internal:host-gateway",
        ZAP_IMAGE, "zap.sh", "-daemon",
        "-host", "0.0.0.0", "-port", str(host_port),
        "-config", f"api.key={api_key}",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
    ], check=True)


def zap_down(name: str = "paperk-zap") -> None:
    _run(["docker", "rm", "-f", name])


def zap_wait_ready(host_port: int = 8090, api_key: str = "paperk", timeout_s: int = 120) -> bool:
    """Block until the ZAP API answers (the daemon takes a while to boot)."""
    import time as _t
    import urllib.request as _u
    url = f"http://127.0.0.1:{host_port}/JSON/core/view/version/?apikey={api_key}"
    deadline = _t.time() + timeout_s
    while _t.time() < deadline:
        try:
            with _u.urlopen(url, timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            _t.sleep(2)
    return False
