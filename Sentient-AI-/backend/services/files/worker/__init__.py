"""The document parser that runs in its own short-lived, isolated process.

Why it exists: parsing a hostile file is the riskiest thing Crawler does with
it, so it happens in a fresh ``python -I`` process with no server secrets in
its environment, its network disabled, memory and CPU limits applied and its
output capped by the parent (services/files/sandbox.py). Nothing in this
package imports the app (core, sqlalchemy, structlog, services.agent).
"""
