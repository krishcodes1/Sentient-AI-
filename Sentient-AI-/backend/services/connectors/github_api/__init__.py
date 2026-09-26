"""Action groups of the GitHub connector, one module per area.

Why it exists: the GitHub connector has about forty actions, too many for one
readable module. Each module here holds one area's ToolSpec tuple and a mixin
with that area's action coroutines; ``services/connectors/github.py``
assembles them into ``GitHubConnector`` and its ``DEFINITION``.

Connects to: the GitHub REST API (api.github.com) through the mixins.
Depends on: ``services.connectors.base`` (HTTP helpers and errors),
``services.connectors.definition`` and ``services.connectors.shaping``.
"""
