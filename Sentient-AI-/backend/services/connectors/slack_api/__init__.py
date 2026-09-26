"""Action groups of the Slack connector, split out of ``services/connectors/slack.py``.

Why it exists: the Slack connector has seventeen actions; keeping them in one
module would pass the ~700 line budget. ``client`` holds the shared plumbing
(tokens, the Web API call helper, error mapping, validation, shaping), ``reads``
the READ actions and ``writes`` the WRITE and DELETE actions. ``slack.py``
assembles them into ``SlackConnector`` and its ``DEFINITION``.

External service: the Slack Web API (https://slack.com/api/). Depends on
``services.connectors.base``, ``definition`` and ``shaping``.
"""
