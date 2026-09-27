"""services/vault/keys: the dev file is 0600 and stable, the platform
provider mints the key once and never over an unreadable store, the
disabled provider always says why, and select_key_provider picks the OS
store on a Mac or PC no matter what the environment says. No real OS store
is touched: the platform is a fake with a dict."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Optional

import pytest

from services.platform.base import SecretStoreUnavailable
from services.vault.keys import (
    DEV_KEY_ENV,
    KEY_BYTES,
    KEY_NAME,
    DevFileKeyProvider,
    DisabledKeyProvider,
    PlatformKeyProvider,
    VaultUnavailable,
    select_key_provider,
)

POSIX_ONLY = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX mode bits")


class FakePlatform:
    """A Platform with a dict for a secret store (mac/windows) or none."""

    def __init__(self, name: str = "mac", *, store: Optional[dict] = None, broken: bool = False):
        self.name = name
        self.store = {} if store is None else store
        self.broken = broken
        self.reads = 0

    def get_secret(self, name: str) -> Optional[bytes]:
        self.reads += 1
        if self.broken:
            raise SecretStoreUnavailable("the Keychain is locked")
        return self.store.get(name)

    def set_secret(self, name: str, value: bytes) -> None:
        if self.broken:
            raise SecretStoreUnavailable("the Keychain is locked")
        self.store[name] = value

    def delete_secret(self, name: str) -> None:
        self.store.pop(name, None)

    def vault_id(self) -> str:
        return "0f8fad5b-d9cb-469f-a165-70867728950e"


class CountingRng:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, n: int) -> bytes:
        self.calls += 1
        return bytes([self.calls]) * n


# -- DevFileKeyProvider -----------------------------------------------------


def test_dev_file_is_created_once_with_32_bytes(tmp_path):
    provider = DevFileKeyProvider(tmp_path / "keys" / "dev.key")
    key = provider.get()
    assert len(key) == KEY_BYTES
    assert (tmp_path / "keys" / "dev.key").read_bytes() == key
    assert DevFileKeyProvider(tmp_path / "keys" / "dev.key").get() == key


@POSIX_ONLY
def test_dev_file_is_0600(tmp_path):
    path = tmp_path / "dev.key"
    DevFileKeyProvider(path).get()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_dev_file_with_the_wrong_length_is_unavailable(tmp_path):
    path = tmp_path / "dev.key"
    path.write_bytes(b"short")
    with pytest.raises(VaultUnavailable, match="32-byte"):
        DevFileKeyProvider(path).get()


@POSIX_ONLY
def test_dev_file_refuses_a_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_bytes(os.urandom(32))
    link = tmp_path / "dev.key"
    link.symlink_to(target)
    with pytest.raises(VaultUnavailable, match="symlink"):
        DevFileKeyProvider(link).get()


# -- PlatformKeyProvider ----------------------------------------------------


def test_platform_provider_mints_the_key_once_and_stores_it():
    platform = FakePlatform()
    rng = CountingRng()
    provider = PlatformKeyProvider(platform, rng=rng)
    first = provider.get()
    assert len(first) == KEY_BYTES and rng.calls == 1
    assert platform.store[KEY_NAME] == first
    # Cached: the second read is no subprocess and no new key.
    assert provider.get() == first and rng.calls == 1 and platform.reads == 1


def test_platform_provider_returns_the_stored_key_without_minting():
    stored = os.urandom(32)
    platform = FakePlatform(store={KEY_NAME: stored})
    rng = CountingRng()
    assert PlatformKeyProvider(platform, rng=rng).get() == stored
    assert rng.calls == 0


def test_platform_provider_never_replaces_a_key_it_cannot_read():
    # A locked keychain must read as unavailable, not as "no key yet":
    # minting a new one would orphan every blob sealed under the old.
    platform = FakePlatform(store={KEY_NAME: os.urandom(32)}, broken=True)
    rng = CountingRng()
    with pytest.raises(VaultUnavailable, match="Keychain is locked"):
        PlatformKeyProvider(platform, rng=rng).get()
    assert rng.calls == 0 and len(platform.store) == 1


def test_platform_provider_check_reads_the_store_but_never_mints():
    """Settings asks `check` on every view; a store with nothing in it is
    available and stays empty until the first card is stored (`get`)."""
    platform = FakePlatform()
    rng = CountingRng()
    provider = PlatformKeyProvider(platform, rng=rng)
    provider.check()
    assert platform.store == {} and rng.calls == 0 and platform.reads == 1
    # A store that cannot answer is reported, not worked around.
    with pytest.raises(VaultUnavailable, match="Keychain is locked"):
        PlatformKeyProvider(FakePlatform(broken=True), rng=rng).check()
    with pytest.raises(VaultUnavailable, match="not usable"):
        PlatformKeyProvider(FakePlatform(store={KEY_NAME: b"tiny"})).check()
    # Once the key is in memory, check is free.
    provider.get()
    provider.check()
    assert platform.reads == 2 and rng.calls == 1


def test_dev_file_check_tolerates_a_missing_file_and_refuses_a_bad_one(tmp_path):
    path = tmp_path / "vault.key"
    DevFileKeyProvider(path).check()
    assert not path.exists()
    path.write_bytes(b"short")
    with pytest.raises(VaultUnavailable, match="32-byte"):
        DevFileKeyProvider(path).check()


def test_platform_provider_refuses_a_stored_key_of_the_wrong_size():
    platform = FakePlatform(store={KEY_NAME: b"tiny"})
    with pytest.raises(VaultUnavailable, match="not usable"):
        PlatformKeyProvider(platform).get()


def test_platform_provider_reports_an_os_error_by_type_only():
    class Failing(FakePlatform):
        def get_secret(self, name: str) -> Optional[bytes]:
            raise PermissionError("/Users/krish/Library/Application Support/Crawler AI/vault-id")

    with pytest.raises(VaultUnavailable) as info:
        PlatformKeyProvider(Failing()).get()
    assert "PermissionError" in str(info.value) and "/Users/krish" not in str(info.value)


# -- DisabledKeyProvider ----------------------------------------------------


def test_disabled_provider_always_raises_its_reason():
    provider = DisabledKeyProvider("The card vault is not available in this environment (container).")
    with pytest.raises(VaultUnavailable, match=r"\(container\)"):
        provider.get()
    with pytest.raises(VaultUnavailable, match=r"\(container\)"):
        provider.check()


# -- select_key_provider ----------------------------------------------------


@pytest.mark.parametrize("name", ["mac", "windows"])
def test_native_platforms_use_the_os_store_and_ignore_the_dev_file(tmp_path, name):
    env = {DEV_KEY_ENV: str(tmp_path / "dev.key")}
    provider = select_key_provider(FakePlatform(name), env=env)
    assert isinstance(provider, PlatformKeyProvider)
    assert not (tmp_path / "dev.key").exists()


@pytest.mark.parametrize("name", ["container", "linux"])
def test_container_and_linux_take_the_dev_file_when_named(tmp_path, name):
    env = {DEV_KEY_ENV: str(tmp_path / "dev.key")}
    provider = select_key_provider(FakePlatform(name), env=env)
    assert isinstance(provider, DevFileKeyProvider)
    assert len(provider.get()) == KEY_BYTES


def test_container_without_a_dev_file_is_disabled_with_the_reason():
    provider = select_key_provider(FakePlatform("container"), env={})
    assert isinstance(provider, DisabledKeyProvider)
    assert provider.reason == "The card vault is not available in this environment (container)."
    with pytest.raises(VaultUnavailable, match="container"):
        provider.get()


def test_a_blank_dev_file_variable_counts_as_unset():
    provider = select_key_provider(FakePlatform("container"), env={DEV_KEY_ENV: "   "})
    assert isinstance(provider, DisabledKeyProvider)


def test_select_reads_the_given_env_not_the_process(tmp_path, monkeypatch):
    monkeypatch.setenv(DEV_KEY_ENV, str(tmp_path / "process.key"))
    assert isinstance(select_key_provider(FakePlatform("container"), env={}), DisabledKeyProvider)
    assert isinstance(select_key_provider(FakePlatform("container")), DevFileKeyProvider)


def test_dev_file_path_is_a_path(tmp_path):
    provider = select_key_provider(FakePlatform("linux"), env={DEV_KEY_ENV: str(tmp_path / "k")})
    assert isinstance(provider, DevFileKeyProvider)
    assert isinstance(provider._path, Path)
