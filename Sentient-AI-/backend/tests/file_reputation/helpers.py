"""Database helpers the file-reputation tests share: an owner (admin) account, the raw check
rows of a person, the request log and the verdict cache as stored.

Why it exists: several test files assert on what is really in the three tables (an encrypted
column holds no plain id, a row expired, a slot was reserved) rather than on what the service
answers, and an owner account is needed wherever the key-rejected alert or the Security tab's
owner wording is tested.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import undefer

from models.file_reputation import FileReputationCall, FileReputationCheck, FileReputationVerdict
from models.user import User
from tests.conftest import make_user


async def make_owner(session_factory: Any, email: str = "owner@example.com") -> tuple[User, str]:
    """An admin account (the install's owner) and its bearer token."""
    user, token = await make_user(session_factory, email)
    async with session_factory() as session:
        await session.execute(update(User).where(User.id == user.id).values(is_admin=True))
        await session.commit()
    user.is_admin = True
    return user, token


async def check_rows(session_factory: Any, user_id: Any = None) -> list[FileReputationCheck]:
    """Every check row (of *user_id*, when given), source_ref loaded."""
    async with session_factory() as session:
        query = select(FileReputationCheck).options(undefer(FileReputationCheck.source_ref))
        if user_id is not None:
            query = query.where(FileReputationCheck.user_id == uuid.UUID(str(user_id)))
        return list((await session.execute(query)).scalars().all())


async def verdict_rows(session_factory: Any) -> list[FileReputationVerdict]:
    async with session_factory() as session:
        return list((await session.execute(select(FileReputationVerdict))).scalars().all())


async def call_rows(session_factory: Any) -> list[FileReputationCall]:
    async with session_factory() as session:
        return list((await session.execute(select(FileReputationCall))).scalars().all())
