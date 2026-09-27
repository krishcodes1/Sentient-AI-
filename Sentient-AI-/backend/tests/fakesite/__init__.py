"""A stdlib fake site on a free IPv4 loopback port (contracts §8).

Started in a daemon thread by the ``fakesite`` fixture; every browser test
drives it instead of a real website. It binds 127.0.0.1 explicitly so the
guard's loopback toggle sees one address on every OS.

``FakeSite(tls=True)`` serves the same pages over HTTPS with a self-signed
certificate (``tls.py``), because the write tiers refuse ``http://``
pages: the ``fakesite_tls`` fixture is how a test gets an ``https://``
checkout that is still local. ``/pay`` accepts a card number that passes
Luhn and redirects to the confirmation page; anything else is declined.
Every request the server handled is recorded (``FakeSite.handled``), so a
test can prove an order never left the browser, not only that the guard
says it stopped one. A WebSocket handshake on any path is accepted and
every text message the server receives on it is recorded as
``("WS", text)``. A GET of a path in ``pages.DELAYS`` is answered after
that many seconds.
"""

from __future__ import annotations

import base64
import hashlib
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlsplit

from tests.fakesite import tls as tls_certs
from tests.fakesite.pages import DELAYS, PAGES, REDIRECTS

_CARD_FIELDS = ("cc-number", "number", "card")
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"  # RFC 6455's handshake constant


def luhn_ok(number: str) -> bool:
    """The card-number checksum every real checkout runs first; the fake
    site declines a number that fails it so a test can tell a real fill
    from a garbled one."""
    digits = [int(ch) for ch in number if ch.isdigit()]
    if len(digits) < 12 or len(digits) != len(number.replace(" ", "").replace("-", "")):
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


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

    def _record(self, method: str, path: str) -> None:
        handled = getattr(self.server, "handled", None)
        if isinstance(handled, list):
            handled.append((method, path))

    def _websocket(self) -> None:
        """Accept the handshake, then record each text message until the
        client closes or goes quiet for 5 s. Nothing is sent back."""
        digest = hashlib.sha1((self.headers["Sec-WebSocket-Key"] + _WS_GUID).encode()).digest()
        self.wfile.write(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + f"Sec-WebSocket-Accept: {base64.b64encode(digest).decode()}\r\n\r\n".encode()
        )
        self.wfile.flush()
        self.close_connection = True
        self.connection.settimeout(5)
        try:
            while len(head := self.rfile.read(2)) == 2:
                opcode, length = head[0] & 0x0F, head[1] & 0x7F
                if length in (126, 127):
                    length = int.from_bytes(self.rfile.read(2 if length == 126 else 8), "big")
                mask = self.rfile.read(4)  # a client always masks
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(self.rfile.read(length)))
                if opcode == 8:
                    return
                if opcode == 1:
                    self._record("WS", data.decode("utf-8", "replace"))
        except OSError:
            return

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        self._record("GET", path)
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self._websocket()
            return
        if path in DELAYS:
            time.sleep(DELAYS[path])
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
        self._record("POST", path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        if path == "/login":
            self._send(303, "text/plain", "", Location="/home", Set_Cookie="session=fake; Path=/")
            return
        if path == "/pay":
            form = parse_qs(body.decode("utf-8", "replace"))
            number = next((form[key][0] for key in _CARD_FIELDS if form.get(key)), "")
            if luhn_ok(number):
                self._send(303, "text/plain", "", Location="/order-confirmed")
            else:
                status, content_type, page = PAGES["/pay-declined"]
                self._send(status, content_type, page)
            return
        if path == "/pay-redirect":
            # The merchant took the card and answers with a redirect that
            # keeps the method: the browser would re-send the POST there.
            self._send(307, "text/plain", "", Location="https://collector.example.test/confirm")
            return
        if path in ("/post", "/sso/otp", "/inner", "/next", "/place-order", "/coupon", "/cart/add",
                    "/bestellung-absenden"):
            self._send(200, "text/html", "<html><body><h1>Thanks</h1></body></html>")
            return
        self._send(404, "text/plain", "not found")


class _Server(ThreadingHTTPServer):
    """The plain server; ``handled`` is the list ``_Handler._record`` fills."""

    handled: list[tuple[str, str]]


class _TLSServer(_Server):
    """The plain server with each accepted connection wrapped in TLS. The
    handshake runs in the request's own thread (not in ``accept``), so a
    browser's speculative connection that never speaks cannot stall the
    listener, and a failed handshake is dropped quietly."""

    def __init__(self, address: tuple[str, int], context: ssl.SSLContext) -> None:
        super().__init__(address, _Handler)
        self._context = context

    def get_request(self):
        sock, address = self.socket.accept()
        wrapped = self._context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return wrapped, address

    def handle_error(self, request, client_address) -> None:
        return  # a handshake the client abandoned; nothing to report


class FakeSite:
    def __init__(self, tls: bool = False) -> None:
        self.cert: Optional[Path] = None
        if tls:
            self.cert, key = tls_certs.self_signed("127.0.0.1")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.cert, key)
            self._server: _Server = _TLSServer(("127.0.0.1", 0), context)
        else:
            self._server = _Server(("127.0.0.1", 0), _Handler)
        self._scheme = "https" if tls else "http"
        # (method, path) of every request the server answered, in order.
        self.handled: list[tuple[str, str]] = []
        self._server.handled = self.handled
        # shutdown() waits up to one poll interval; the 0.5 s default would
        # add half a second to every browser test's teardown.
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )

    @property
    def base(self) -> str:
        host, port = self._server.server_address[:2]
        return f"{self._scheme}://{host}:{port}"

    def url(self, path: str) -> str:
        return self.base + path

    def start(self) -> "FakeSite":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self.cert is not None:
            tls_certs.remove(self.cert)

