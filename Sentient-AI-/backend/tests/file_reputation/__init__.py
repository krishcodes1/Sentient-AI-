"""Tests for file reputation (security wave S10): the VirusTotal client, the limits, the verdict
cache, the byte holder, the fingerprinting helpers and the texts built from a verdict.

Why it exists: marks the directory as a package so the tests share the fakes in fakevt.py
(``FakeVirusTotal`` behind ``httpx.MockTransport``, fixed fake keys, clocks). No test here
reaches the network or DNS: conftest.py replaces ``check_ssrf`` for every test in the package.
"""
