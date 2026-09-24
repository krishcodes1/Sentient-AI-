from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="web_browsing",
    label="Browse the web",
    description="Search the public web and read pages as text to answer questions and research tasks.",
    tools=("web.search", "web.fetch_page"),
    default_enabled=True,
    risk="low",
    when_denied="Web browsing is turned off. The owner can turn it on in Settings → Permissions.",
)
