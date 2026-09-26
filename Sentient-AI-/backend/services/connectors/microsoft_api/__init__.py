"""Action groups of the Microsoft 365 connector, one module per area.

Why it exists: the connector covers Outlook mail, calendar, OneDrive, To Do
and contacts (spec section 5.5), which is too much for one readable file.
Each module here exports an ``<AREA>_ACTIONS`` tuple of ToolSpecs and a mixin
class holding those action coroutines; ``services/connectors/microsoft.py``
assembles them into ``MicrosoftConnector`` and its ``DEFINITION``.
Talks to Microsoft Graph (https://graph.microsoft.com/v1.0) through the
shared helpers in ``common.py`` and ``services/connectors/base.py``.
"""
