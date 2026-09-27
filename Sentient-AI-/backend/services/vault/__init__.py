"""The card vault: the owner's payment card, sealed with a key that only the
OS secret store holds, opened only at a checkout the owner approved.

Why it exists: A personal assistant keeps the card in its purse and never
shows it to anyone. This package is that purse for Crawler (purchases spec
§4): ``keys`` decides where the key lives (Keychain, DPAPI, a dev file in
tests, or nowhere in a container), ``crypto`` seals and opens blobs bound to
their own row, and ``service`` is the only reader and writer of the
``vault_items`` table. No API and no model-facing result ever carries the
plaintext or the blob; the views here are masked by construction.
"""

from services.vault.keys import (
    DEV_KEY_ENV,
    DevFileKeyProvider,
    DisabledKeyProvider,
    KeyProvider,
    PlatformKeyProvider,
    VaultUnavailable,
    select_key_provider,
)
from services.vault.service import CardSecret, VaultItemView, VaultService

__all__ = [
    "DEV_KEY_ENV",
    "CardSecret",
    "DevFileKeyProvider",
    "DisabledKeyProvider",
    "KeyProvider",
    "PlatformKeyProvider",
    "VaultItemView",
    "VaultService",
    "VaultUnavailable",
    "select_key_provider",
]
