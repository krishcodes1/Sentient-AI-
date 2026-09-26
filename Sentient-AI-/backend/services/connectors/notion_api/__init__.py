"""Action and helper package for the Notion connector
(services/connectors/notion.py).

Why it exists: the Notion actions, the Markdown and block translation and the
property handling together would push one module well past a readable size.
Splitting them here lets ``notion.py`` hold only the credentials, headers,
health check and ``DEFINITION``, and combine the action mixins into one class.

It connects to services/connectors/notion.py only. It talks to the Notion
REST API (https://api.notion.com/v1) through ``common``, ``reads`` and
``writes``. Modules: ``common`` (shared constants, id checks, pagination and
request helpers), ``reads`` (read actions), ``writes`` (write and delete
actions, each gated by approval), ``markdown`` (block renderer and parser,
rich-text limits) and ``properties`` (property rendering and write-value
building). ``markdown`` and ``properties`` are pure data work with no I/O.
"""
