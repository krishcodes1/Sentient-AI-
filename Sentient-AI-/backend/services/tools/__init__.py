"""Built-in agent tools.

Unlike ``services.connectors``, nothing here holds credentials or needs a
connector row: these are the capabilities every user gets. That also
makes them the tools most likely to be pointed at a hostile URL, so the
egress guard in ``services.tools.net`` is not optional decoration — it
is the reason this package can exist at all.
"""
