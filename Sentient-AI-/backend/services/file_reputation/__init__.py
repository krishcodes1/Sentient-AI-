"""File reputation (security wave S10): looks the SHA-256 fingerprint of files people send
Crawler, and of email attachments, up in VirusTotal with the owner's own key, and sends a file
VirusTotal does not know only after an approval card for that one file.

Why it exists: a file someone sends can be malware, and VirusTotal already knows most malware by
its fingerprint. Only the fingerprint leaves the machine for a lookup; the bytes go out only for
an approved upload. This package holds the network client, so it lives apart from
services/security, which is local only (services/security/README.md).

Modules: ``virustotal`` (the client and the verdict mapping), ``quota`` (VirusTotal's per-key
limits over the request log), ``store`` (the three tables), ``holder`` (bytes kept in memory for
an upload card), ``byte_sink`` (fingerprinting helpers and the hand-off of re-fetched attachment
bytes; standard library only), ``kinds`` (which files count as risky), ``verdicts`` (``FileVerdict``
and its sentences), ``alerts`` (alert texts), and the service, toolkit, sweeper and call check
that tie them together.

Nothing is imported here: the Gmail and Outlook connectors import ``byte_sink`` and must not pull
the client, the database or the service in with it.
"""
