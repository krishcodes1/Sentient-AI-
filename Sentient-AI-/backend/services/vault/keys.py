"""Where the vault key lives: the OS secret store on a Mac or PC, a 0600
file in tests, nowhere in a container (purchases spec §4).

Why it exists: The card blobs in the database are only as private as the
key that seals them, so the key must never sit next to them. A
``KeyProvider`` answers ``get()`` with the 32 bytes or raises
``VaultUnavailable`` with a reason the owner can read; ``select_key_provider``
is the one place that maps a platform to a provider, and it honours the
dev-file override only where there is no OS store to prefer.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable, Mapping, Optional, Protocol

import structlog

from services.platform.base import Platform, SecretStoreUnavailable

logger = structlog.get_logger(__name__)

KEY_BYTES = 32
# The name the key is filed under in the OS store (a Keychain account
# suffix on Mac, a file stem on Windows).
KEY_NAME = "vault-key"
DEV_KEY_ENV = "CRAWLER_VAULT_DEV_KEY_FILE"
_PLATFORM_STORES = ("mac", "windows")


class VaultUnavailable(Exception):
    """The vault cannot be used right now; ``str(exc)`` is the reason shown
    to the owner (the API's 409, the checkout precheck's refusal)."""


class KeyProvider(Protocol):
    def get(self) -> bytes:
        """The 32-byte vault key, or VaultUnavailable."""

    def check(self) -> None:
        """VaultUnavailable when ``get`` could not answer right now; returns
        quietly otherwise, *without* minting a key. What the Settings page
        asks on every view: a key store the owner has not used yet must
        stay empty until the first card is stored."""


class PlatformKeyProvider:
    """The key from the OS secret store, minted on first use of ``get``
    (the first card stored), never by ``check``.

    Kept in memory after the first successful read: on a Mac every read
    is a ``security`` subprocess and may prompt for the login keychain,
    and a checkout should not ask twice. A store that cannot be read is
    never worked around by minting a new key (see SecretStoreUnavailable).
    """

    def __init__(self, platform: Platform, *, rng: Callable[[int], bytes] = os.urandom) -> None:
        self._platform = platform
        self._rng = rng
        self._key: Optional[bytes] = None

    def _stored(self) -> Optional[bytes]:
        """The key in the OS store, None when none is stored yet, or
        VaultUnavailable with the reason the owner reads."""
        try:
            key = self._platform.get_secret(KEY_NAME)
        except SecretStoreUnavailable as exc:
            raise VaultUnavailable(str(exc)) from exc
        except (OSError, ValueError) as exc:
            # Type only: an OSError message can name the id file's path.
            logger.warning("vault_key_store_failed", error_type=type(exc).__name__)
            raise VaultUnavailable(
                f"The card vault's key store failed ({type(exc).__name__})."
            ) from exc
        if key is not None and len(key) != KEY_BYTES:
            raise VaultUnavailable("The card vault key in the OS store is not usable.")
        return key

    def check(self) -> None:
        # Opening Settings must not write a Keychain item: a store that
        # answers "nothing stored" is available, and the key is minted
        # when the first card is.
        if self._key is None:
            self._stored()

    def get(self) -> bytes:
        if self._key is not None:
            return self._key
        key = self._stored()
        if key is None:
            key = self._rng(KEY_BYTES)
            try:
                self._platform.set_secret(KEY_NAME, key)
            except SecretStoreUnavailable as exc:
                raise VaultUnavailable(str(exc)) from exc
            except (OSError, ValueError) as exc:
                logger.warning("vault_key_store_failed", error_type=type(exc).__name__)
                raise VaultUnavailable(
                    f"The card vault's key store failed ({type(exc).__name__})."
                ) from exc
            logger.info("vault_key_created", platform=self._platform.name)
        self._key = key
        return key


class DevFileKeyProvider:
    """A key in a 0600 file, for the test suite and a developer's Linux
    box only. ``select_key_provider`` never picks this on a Mac or PC, so
    the env var cannot downgrade a real install's custody."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)

    def check(self) -> None:
        # A missing file is fine (created by the first get); a file that is
        # there must be a usable key.
        if self._path.exists() or self._path.is_symlink():
            self.get()

    def get(self) -> bytes:
        path = self._path
        try:
            if path.is_symlink():
                raise VaultUnavailable("The dev key file is a symlink.")
            try:
                key = path.read_bytes()
            except FileNotFoundError:
                key = self._create()
        except OSError as exc:
            raise VaultUnavailable(f"The dev key file could not be read ({type(exc).__name__}).")
        if len(key) != KEY_BYTES:
            raise VaultUnavailable("The dev key file does not hold a 32-byte key.")
        return key

    def _create(self) -> bytes:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        key = os.urandom(KEY_BYTES)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        # mkdir/open honour the umask for the directory but the mode above
        # is exact for the file; make sure of it on platforms that apply it.
        os.chmod(self._path, stat.S_IRUSR | stat.S_IWUSR)
        return key


class DisabledKeyProvider:
    """No key anywhere: every ``get`` raises with the reason. This is what
    a container gets, so the Settings page can say why the card form is
    missing instead of failing later at a checkout."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def check(self) -> None:
        raise VaultUnavailable(self.reason)

    def get(self) -> bytes:
        raise VaultUnavailable(self.reason)


def select_key_provider(platform: Platform, env: Mapping[str, str] = os.environ) -> KeyProvider:
    """Mac/Windows: the OS store, always. Container/Linux: the dev file
    when ``CRAWLER_VAULT_DEV_KEY_FILE`` names one, else disabled."""
    if platform.name in _PLATFORM_STORES:
        return PlatformKeyProvider(platform)
    dev_file = (env.get(DEV_KEY_ENV) or "").strip()
    if dev_file:
        logger.warning("vault_dev_key_file_in_use", platform=platform.name)
        return DevFileKeyProvider(Path(dev_file))
    return DisabledKeyProvider(
        f"The card vault is not available in this environment ({platform.name})."
    )
