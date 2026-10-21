"""Network clients for outside security services; services/security stays local.

Why it exists: the security wave's lookups (Google Safe Browsing / Web Risk
for links, and the owner key registry those clients share) send data to a
third party with the owner's own key, so they live apart from the local,
stdlib-only detectors in services/security. Every request goes through the
SSRF-guarded client under its own network policy (core/network_security.py),
and nothing is sent without a key.
"""
