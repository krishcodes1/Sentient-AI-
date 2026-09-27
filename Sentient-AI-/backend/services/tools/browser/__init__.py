"""Browser toolkit (browser-control spec §4, purchases spec §5–§6):
session, snapshot, actions (browser.read), act (browser.act), checkout/
(browser.checkout), pagememory (the page the last read observed, which
act and checkout are checked against), _shared (the helpers read and act
have in common), login, handoff, guard.

Modules are imported by their own paths (``services.tools.browser.actions``
etc.); this file deliberately re-exports nothing so importing one module
never executes the others.
"""
