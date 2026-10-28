"""Interaction server: an isolated HTTP listener for blind outcomes (blind RCE, SSRF,
out-of-band deserialization). The target can reach only this server; a successful blind
exploit calls back carrying its nonce, which is logged here. Self-hosted so the corpus
stays offline and reproducible (design s10).

DNS exfil is out of scope for v0.1 (HTTP callback covers the planted-payload cases we
control). Add a DNS listener later only if a target needs it.
"""
from __future__ import annotations
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class _Log:
    def __init__(self) -> None:
        self._hits: list[str] = []
        self._lock = threading.Lock()

    def add(self, token: str) -> None:
        with self._lock:
            self._hits.append(token)

    def seen(self, nonce: str) -> bool:
        with self._lock:
            return any(nonce in h for h in self._hits)

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self._hits)


class InteractionServer:
    """Usage:
        with InteractionServer() as srv:
            url = srv.callback_url            # hand this base into the exploit payload
            ...                               # agent triggers the target
            if srv.log.seen(nonce): ...       # confirmed blind outcome
    """
    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.log = _Log()
        log = self.log

        class Handler(BaseHTTPRequestHandler):
            def _record(self):
                # the nonce is expected anywhere in the path or query
                log.add(urlsplit(self.path).path + "?" + (urlsplit(self.path).query or ""))
                self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

            do_GET = _record
            do_POST = _record

            def log_message(self, *a):  # silence default stderr spam
                return

        self._server = ThreadingHTTPServer((host, port), Handler)
        self.host, self.port = self._server.server_address[0], self._server.server_address[1]

    @property
    def callback_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> "InteractionServer":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
