"""Action groups of the Google Workspace connector, split out of
``services/connectors/google_workspace.py``.

Why it exists: Google Workspace has well over forty actions across six APIs;
one module would blow far past the ~700 line budget. ``client`` holds the
shared plumbing (tokens, refresh, the request helper, validation and text
helpers); ``mime`` parses and builds Gmail messages; ``gmail``, ``calendar``, ``drive``, ``docs``, ``sheets`` and
``contacts`` each export an ``<AREA>_ACTIONS`` tuple and a mixin class with
those action coroutines. ``google_workspace.py`` assembles them into
``GoogleWorkspaceConnector`` and its ``DEFINITION``.

External services: the Gmail, Calendar, Drive, Docs, Sheets and People REST
APIs plus Google's OAuth token endpoints. Depends on
``services.connectors.base``, ``definition`` and ``shaping``.
"""
