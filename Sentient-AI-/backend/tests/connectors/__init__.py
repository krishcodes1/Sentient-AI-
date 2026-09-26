"""Per-connector test modules (tests/connectors/test_<key>.py).

Why it exists: makes this directory a package, like tests/, so modules here
import as tests.connectors.<name> and never clash with a top-level test name.
"""
