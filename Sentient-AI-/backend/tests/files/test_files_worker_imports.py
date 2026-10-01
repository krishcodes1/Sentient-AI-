"""Tests that the parser worker never loads the app: importing its entry
script and every parser pulls in no core, sqlalchemy, structlog or
services.agent module.

Why it exists: the worker's isolation relies on it holding nothing of the
server's (no database engine, no settings object that reads secrets, no
logging setup); a stray import would quietly bring all of that in.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_the_worker_and_its_parsers_import_nothing_from_the_app():
    code = textwrap.dedent(
        f"""
        import json, sys
        sys.path.insert(0, {BACKEND!r})
        import services.files.worker.main
        import services.files.worker.limits
        import services.files.worker.protocol
        from services.files.worker.parsers import image, ooxml, pdf, text, xlsx
        loaded = sorted(
            m for m in sys.modules
            if m.split(".")[0] in ("core", "sqlalchemy", "structlog", "models", "api")
            or m.startswith("services.agent")
            or m.startswith("services.capabilities")
        )
        print(json.dumps(loaded))
        """
    )
    result = subprocess.run(  # noqa: S603 - a fixed test script
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []
