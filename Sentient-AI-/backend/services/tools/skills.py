"""Implements the skills.read built-in tool: the instructions of one of the
caller's enabled skills, by name.

Why it exists: the prompt lists only each skill's name and description
(services/skills.py); this is how the model gets a skill's instructions on
the turn that needs them. The runtime shows them outside the untrusted-data
fence (services/agent/runtime.py, _user_skill), because they are the user's
own words. The skill is looked up under the executor's user_id, never the
model's, and a skill that is turned off reads as missing.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Optional

from sqlalchemy import select

from models.skill import Skill


class SkillToolkit:
    def __init__(self, session_factory: Optional[Callable[[], Any]] = None) -> None:
        self._session_factory = session_factory

    async def execute(self, action: str, params: dict[str, Any], user_id: str) -> dict[str, Any]:
        name = params.get("name")
        if action != "read" or not isinstance(name, str):
            return {"ok": False, "error": "skills.read takes the name of one of the user's skills."}
        if self._session_factory is None:
            return {"ok": False, "error": "Skills are not available here."}
        async with self._session_factory() as session:
            skill = (
                await session.execute(
                    select(Skill).where(
                        Skill.user_id == uuid.UUID(str(user_id)),
                        Skill.name == name.strip().lower(),
                        Skill.enabled.is_(True),
                    )
                )
            ).scalar_one_or_none()
        if skill is None:
            return {"ok": False, "error": f"No skill named '{name}' is turned on."}
        return {"ok": True, "name": skill.name, "instructions": skill.instructions}
