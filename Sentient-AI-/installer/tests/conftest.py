"""Make installer/bootstrap.py importable as ``bootstrap`` in these tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
