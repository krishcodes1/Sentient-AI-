"""Docker/CI: Playwright's headless Chromium, nothing persistent on disk
(the per-user storage_state is an encrypted blob in the database, phase
2), no window to raise, and no secret store: the card vault is disabled
here (purchases spec §2), so no vault id is minted on the scratch disk
either — one there would change on every restart."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

from services.platform.base import PlatformName, SecretStoreUnavailable
from services.platform.linux import LinuxPlatform


class ContainerPlatform(LinuxPlatform):
    name: PlatformName = "container"

    def browser_channel(self) -> Optional[str]:
        # The image ships Playwright's Chromium; there is no Chrome or Edge.
        return None

    def data_dir(self) -> Path:
        # Scratch only: a container's disk is disposable and nothing secret
        # is written here (spec §11.1: in-memory + encrypted storage_state).
        return Path(tempfile.gettempdir()) / "crawler-ai"

    def vault_id(self) -> str:
        raise SecretStoreUnavailable("A container has no secret store and no stable vault id.")
