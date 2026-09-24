from services.capabilities.base import Capability

CAPABILITY = Capability(
    key="installs",
    label="Install optional software (asks first)",
    description="Install optional components from a fixed list, such as the hidden browser, after asking you each time.",
    tools=("system.install_capability",),
    default_enabled=True,
    risk="medium",
    when_denied="Installing software is turned off. The owner can turn it on in Settings → Permissions.",
)
