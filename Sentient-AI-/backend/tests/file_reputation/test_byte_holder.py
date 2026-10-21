"""Tests for services/file_reputation/holder.py, the in-memory holder of bytes an approved upload
card may send: they prove held bytes expire, the holder stays within its bounds by evicting the
least recently used unpinned entries first, one user never reads another's bytes, pinning keeps
a carded file longer, and only a file the owner picked counts as explicit.

Why it exists: web-chat, Slack and Security-page files cannot be fetched again, so their bytes
wait here, and only here, for an approval. The holder must stay small, forget on time, and never
let a chat card send a personal document (review SEC-F2). A monotonic clock is injected, so no
test waits.
"""

from __future__ import annotations

import pytest

from services.file_reputation.holder import ByteHolder
from tests.file_reputation.fakevt import MonotonicClock, sha_of

ALICE = "11111111-1111-1111-1111-111111111111"
BOB = "22222222-2222-2222-2222-222222222222"


def blob(label: str, size: int = 10) -> tuple[str, bytes]:
    data = (label.encode() * size)[:size]
    return sha_of(data), data


def test_held_bytes_expire_after_their_ttl():
    clock = MonotonicClock()
    holder = ByteHolder(clock=clock)
    sha, data = blob("setup")

    holder.put(ALICE, sha, data, ttl_s=1800)
    clock.now += 1799
    assert holder.get(ALICE, sha) == data
    clock.now += 1
    assert holder.get(ALICE, sha) is None
    assert holder.total_bytes == 0 and len(holder) == 0
    # Nothing is held for a zero or negative lifetime, or for empty bytes.
    holder.put(ALICE, sha, data, ttl_s=0)
    holder.put(ALICE, sha, b"", ttl_s=60)
    assert len(holder) == 0


def test_the_holder_evicts_least_recently_used_unpinned_entries_first():
    clock = MonotonicClock()
    holder = ByteHolder(max_per_user=3, clock=clock)
    (a, da), (b, db), (c, dc), (d, dd) = (blob(x) for x in "abcd")

    holder.put(ALICE, a, da, ttl_s=600)
    holder.put(ALICE, b, db, ttl_s=600)
    holder.put(ALICE, c, dc, ttl_s=600)
    assert holder.pin(ALICE, a, ttl_s=3600)
    holder.get(ALICE, b)  # b is now used more recently than c
    holder.put(ALICE, d, dd, ttl_s=600)

    # Three files per user: c, the least recently used unpinned one, went first.
    assert [holder.has(ALICE, x) for x in (a, b, c, d)] == [True, True, False, True]

    # The whole-holder bound: with only pinned entries left, the oldest pinned one goes.
    small = ByteHolder(max_total_bytes=25, clock=clock)
    (e, de), (f, df), (g, dg) = (blob(x) for x in "efg")
    small.put(ALICE, e, de, ttl_s=600)
    small.put(BOB, f, df, ttl_s=600)
    small.pin(ALICE, e, ttl_s=600)
    small.pin(BOB, f, ttl_s=600)
    small.put(ALICE, g, dg, ttl_s=600)
    assert [small.has(ALICE, e), small.has(BOB, f), small.has(ALICE, g)] == [False, True, True]
    assert small.total_bytes == 20


def test_a_user_never_reads_another_users_held_bytes():
    holder = ByteHolder(clock=MonotonicClock())
    sha, data = blob("shared")

    holder.put(ALICE, sha, data, ttl_s=600, explicit=True)

    assert holder.get(ALICE, sha) == data
    assert holder.get(BOB, sha) is None
    assert not holder.has(BOB, sha)
    assert not holder.has_explicit(BOB, sha)
    assert not holder.pin(BOB, sha, ttl_s=600)
    holder.drop(BOB, sha)
    assert holder.get(ALICE, sha) == data
    assert holder.get("", sha) is None


def test_pinning_extends_an_entry_and_fails_when_it_is_gone():
    clock = MonotonicClock()
    holder = ByteHolder(clock=clock)
    sha, data = blob("carded")

    holder.put(ALICE, sha, data, ttl_s=1800)
    clock.now += 1000
    assert holder.pin(ALICE, sha, ttl_s=3600) is True
    clock.now += 3599
    assert holder.get(ALICE, sha) == data
    clock.now += 1
    assert holder.get(ALICE, sha) is None
    assert holder.pin(ALICE, sha, ttl_s=3600) is False
    # Pinning never shortens an entry.
    holder.put(ALICE, sha, data, ttl_s=7200)
    assert holder.pin(ALICE, sha, ttl_s=10)
    clock.now += 7199
    assert holder.has(ALICE, sha)


def test_only_bytes_the_owner_picked_count_as_explicit_and_they_stay_explicit():
    holder = ByteHolder(clock=MonotonicClock())
    chat_sha, chat_data = blob("from-chat")
    page_sha, page_data = blob("from-page")

    holder.put(ALICE, chat_sha, chat_data, ttl_s=1800)
    holder.put(ALICE, page_sha, page_data, ttl_s=3600, explicit=True)
    # The same file arriving again in chat does not undo the owner's pick.
    holder.put(ALICE, page_sha, page_data, ttl_s=60)

    assert holder.has_explicit(ALICE, page_sha)
    assert not holder.has_explicit(ALICE, chat_sha)
    assert holder.total_bytes == len(chat_data) + len(page_data)


def test_a_file_larger_than_the_whole_holder_is_not_held():
    holder = ByteHolder(max_total_bytes=8, clock=MonotonicClock())
    sha, data = blob("too-big", size=9)

    holder.put(ALICE, sha, data, ttl_s=600)

    assert holder.get(ALICE, sha) is None and holder.total_bytes == 0


def test_drop_and_drop_user_forget_bytes_at_once_and_fingerprints_match_in_any_case():
    holder = ByteHolder(clock=MonotonicClock())
    (a, da), (b, db) = blob("a"), blob("b")

    holder.put(ALICE, a.upper(), da, ttl_s=600)
    holder.put(ALICE, b, db, ttl_s=600)
    holder.put(BOB, b, db, ttl_s=600)

    assert holder.get(ALICE, a) == da
    holder.drop(ALICE, a)
    assert holder.get(ALICE, a.upper()) is None
    holder.drop_user(ALICE)
    assert not holder.has(ALICE, b) and holder.has(BOB, b)
    assert holder.total_bytes == len(db)
    # A value that is not a fingerprint is never a key.
    holder.put(ALICE, "not-a-fingerprint", da, ttl_s=600)
    assert len(holder) == 1


def test_a_holder_needs_room_for_one_file():
    with pytest.raises(ValueError):
        ByteHolder(max_total_bytes=0)
    with pytest.raises(ValueError):
        ByteHolder(max_per_user=0)
