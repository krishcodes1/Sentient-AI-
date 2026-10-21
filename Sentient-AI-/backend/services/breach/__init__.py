"""The breach monitor's building blocks (security S6): watched-address handling,
the Have I Been Pwned v3 client, the Pwned Passwords range client, the
breach-watch store and the alert texts.

Why it exists: the breach monitor talks to two outside services, so its
clients live here and not in ``services/security``, whose detector modules are
local only (no network, no model). Every request goes through the SSRF-guarded
client under a fixed per-vendor network policy (``egress.py``); the owner's
HIBP key travels only in a request header, and no log line, audit row or
exception message ever carries an address, a key or a password-hash prefix.

Modules: ``addresses`` (normalise, digest, seal and hint an address; pure),
``egress`` (the guarded client's policy resolver), ``hibp`` (breachedaccount
and subscription/status, the pacer, the key tester), ``pwned_passwords``
(the k-anonymity range lookup behind the password-check proxy), ``store``
(every read and write of the two breach-watch tables, the seen list) and
``messages`` (model-free alert texts and failure sentences). The weekly
sweeper is ``services/notifications/breach_monitor.py``.

Connects to: services/notifications/breach_monitor.py (the sweeper),
api/routes/security_breach.py, services/reputation/keys.py (the key tester),
api/routes/auth.py (the export), main.py.
"""
