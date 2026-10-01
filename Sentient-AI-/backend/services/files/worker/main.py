"""Entry script of the parser worker: ``python -I <this file>``, the file on
stdin, NDJSON sections on stdout.

Why it exists: every document is parsed in a fresh process that holds no
secrets, cannot reach the network and runs under memory and CPU limits, so a
hostile file can at most fail its own parse. In order, it: reads the header
line, applies its limits (worker/limits.py), replaces socket.socket,
create_connection and getaddrinfo with ones that raise, reads exactly the
announced number of bytes, then dispatches to one parser, which reports
through the protocol (worker/protocol.py). The ``-I`` flag means no
PYTHON* environment variables, no user site-packages and no script
directory on the path; the backend root is put on the path by hand so the
parser modules import.

Imports nothing from the app: no core, sqlalchemy, structlog or
services.agent (tests/files/test_files_worker_imports.py holds that).
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Callable

# The largest file the worker will read from stdin, whatever the header says
# (the parent's presets stay well under it).
_MAX_INPUT_BYTES = 64 * 1024 * 1024


def _backend_root() -> str:
    # worker/main.py -> worker -> files -> services -> backend
    here = os.path.abspath(__file__)
    for _ in range(4):
        here = os.path.dirname(here)
    return here


def disable_network() -> None:
    """Make every new socket, connection and lookup in this process fail.
    socket.socket stays a class (a subclass whose constructor raises), so a
    module that subclasses it at import still loads."""
    import socket

    message = "network access is disabled in the file worker"

    class _NoSocket(socket.socket):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise OSError(message)

    def _refuse(*args: Any, **kwargs: Any) -> Any:
        raise OSError(message)

    socket.socket = _NoSocket  # type: ignore[misc]
    socket.create_connection = _refuse
    socket.getaddrinfo = _refuse
    socket.socketpair = _refuse
    socket.fromfd = _refuse


def _parser_for(kind: str) -> Callable[..., None]:
    if kind == "pdf":
        from services.files.worker.parsers import pdf

        return pdf.parse
    if kind == "docx":
        from services.files.worker.parsers import ooxml

        return ooxml.parse_docx
    if kind == "pptx":
        from services.files.worker.parsers import ooxml

        return ooxml.parse_pptx
    if kind == "xlsx":
        from services.files.worker.parsers import xlsx

        return xlsx.parse
    if kind in ("text", "markdown", "csv", "json", "html"):
        from services.files.worker.parsers import text

        return text.parse
    if kind == "image":
        from services.files.worker.parsers import image

        return image.parse
    from services.files.worker.protocol import ParseError

    raise ParseError("unsupported")


def run(header: dict[str, Any], data: bytes, write: Callable[[bytes], None]) -> None:
    """Parse *data* as the header's kind, reporting through *write* (one
    protocol line per call). Never raises: a refusal or a crash in the
    parser becomes an ``error`` line. Used by main() in the worker process
    and by the in-process sandbox in tests."""
    from services.files.worker.protocol import Emitter, ParseError

    emitter = Emitter(write)
    try:
        parser = _parser_for(str(header.get("kind") or ""))
        parser(data, header, emitter)
    except ParseError as exc:
        emitter.error(exc.code)
    except MemoryError:
        emitter.error("too_large")
    except RecursionError:
        emitter.error("corrupt")
    except Exception:  # noqa: BLE001 - any parser failure is a damaged file
        emitter.error("corrupt")


def _read_exactly(stream: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    left = size
    while left > 0:
        chunk = stream.read(min(left, 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def main() -> int:
    root = _backend_root()
    if root not in sys.path:
        sys.path.insert(0, root)
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    from services.files.worker.protocol import MAX_HEADER_BYTES, Emitter

    def write(line: bytes) -> None:
        stdout.write(line)
        stdout.flush()

    try:
        header = json.loads(stdin.readline(MAX_HEADER_BYTES) or b"{}")
        if not isinstance(header, dict):
            raise ValueError("header")
    except ValueError:
        Emitter(write).error("corrupt")
        return 2

    from services.files.worker.limits import apply_limits

    apply_limits(float(header.get("deadline_s") or 60.0))
    disable_network()

    try:
        size = int(header.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    if size <= 0 or size > _MAX_INPUT_BYTES:
        Emitter(write).error("too_large" if size > 0 else "empty")
        return 0
    data = _read_exactly(stdin, size)
    run(header, data, write)
    return 0


if __name__ == "__main__":
    sys.exit(main())
