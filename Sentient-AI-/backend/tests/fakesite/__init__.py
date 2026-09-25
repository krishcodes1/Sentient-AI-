"""A stdlib fake site on a free IPv4 loopback port (contracts §8).

Started in a daemon thread by the ``fakesite`` fixture; every browser test
drives it instead of a real website. It binds 127.0.0.1 explicitly so the
guard's loopback toggle sees one address on every OS.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from tests.fakesite.pages import PAGES, REDIRECTS


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # keep pytest output clean
        return

    def _send(self, status: int, content_type: str, body: str, **headers: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in headers.items():
            self.send_header(key.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in REDIRECTS:
            self._send(302, "text/plain", "", Location=REDIRECTS[path])
            return
        if path in PAGES:
            status, content_type, body = PAGES[path]
            self._send(status, content_type, body)
            return
        self._send(404, "text/plain", "not found")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if path == "/login":
            self._send(303, "text/plain", "", Location="/home", Set_Cookie="session=fake; Path=/")
            return
        if path in ("/post", "/sso/otp", "/inner", "/next", "/pay"):
            self._send(200, "text/html", "<html><body><h1>Thanks</h1></body></html>")
            return
        self._send(404, "text/plain", "not found")


class FakeSite:
    def __init__(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        # shutdown() waits up to one poll interval; the 0.5 s default would
        # add half a second to every browser test's teardown.
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )

    @property
    def base(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def url(self, path: str) -> str:
        return self.base + path

    def start(self) -> "FakeSite":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
