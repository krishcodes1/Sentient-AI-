"""Puts the installer/ directory on sys.path so these tests can ``import bootstrap``.

Why it exists: installer/ is not a package and bootstrap.py is normally run as a script
by the launchers, so without this insert pytest would fail at collection with
ModuleNotFoundError; pytest loads this file automatically for every test in the directory.

Make installer/bootstrap.py importable as ``bootstrap`` in these tests.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
