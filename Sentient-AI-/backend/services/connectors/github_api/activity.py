"""GitHub notification, release and gist actions: list and mark
notifications read, list and read releases, create draft releases and
publish them, and create gists.

Why it exists: the "Other" row of the GitHub table in the connectors spec
(section 5.2). ``services/connectors/github.py`` mixes ``ActivityMixin`` into
``GitHubConnector`` and lists ``ACTIVITY_ACTIONS`` in its DEFINITION.
Releases are always created as drafts; publishing is a separate,
always-confirmed step. Gists are secret unless the user asks otherwise.

Connects to: the GitHub REST API (``/notifications``,
``/repos/<o>/<r>/releases...``, ``/gists``). Notifications need a classic
token or the device flow: fine-grained tokens cannot read them. Depends on
``github_api.common`` and ``services.connectors.shaping``.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from services.agent import risk
from services.agent.permissions import ActionCategory
from services.connectors.base import ConnectorError, path_segment
from services.connectors.definition import ToolSpec, _schema
from services.connectors.shaping import clamp_limit

from .common import (
    LIMIT_PROP,
    OWNER_PROP,
    REPO_PROP,
    GitHubApiBase,
    as_list,
    as_object,
    body_fields,
    flag,
    git_ref,
    login,
    nested,
    nested_str,
    positive_int,
    preview,
    repo_path,
    require_confirmation,
    scalars,
    text_arg,
)

MAX_RELEASE_BODY_CHARS = 6_000
# Largest gist file accepted (characters).
MAX_GIST_CHARS = 1_000_000
_GIST_FILENAME_RE = re.compile(r"^[^/\\\x00-\x1f]{1,255}$")
_THREAD_ID_RE = re.compile(r"^[0-9]{1,20}$")

_RELEASE_ID_PROP = {
    "type": "integer",
    "description": "Release id (from list_releases)",
    "required": True,
}

ACTIVITY_ACTIONS: tuple[ToolSpec, ...] = (
    ToolSpec(
        "list_notifications",
        "List your GitHub notifications (unread only unless include_read is true).",
        ActionCategory.READ,
        _schema(
            include_read={"type": "boolean", "description": "Include notifications already read"},
            participating={"type": "boolean", "description": "Only threads you take part in"},
            limit=LIMIT_PROP,
        ),
        required_scope="notifications.read",
    ),
    ToolSpec(
        "list_releases",
        "List a repository's releases, newest first (drafts too when you can push).",
        ActionCategory.READ,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, limit=LIMIT_PROP),
        required_scope="releases.read",
    ),
    ToolSpec(
        "get_release",
        "Read one release by id or tag (default: the latest published release), with its notes.",
        ActionCategory.READ,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            release_id={"type": "integer", "description": "Release id"},
            tag={"type": "string", "description": "Tag name, like v1.2.0"},
        ),
        required_scope="releases.read",
    ),
    ToolSpec(
        "mark_notification_read",
        "Mark one notification thread as read.",
        ActionCategory.WRITE,
        _schema(
            thread_id={"type": "string", "description": "Notification thread id", "required": True},
        ),
        required_scope="notifications.write",
        risk="low",
        ref_args=("thread_id",),
        low_risk_note="mark GitHub notifications read",
    ),
    ToolSpec(
        "create_release",
        "Create a DRAFT release for a tag (not visible to others until publish_release).",
        ActionCategory.WRITE,
        _schema(
            owner=OWNER_PROP,
            repo=REPO_PROP,
            tag_name={
                "type": "string",
                "description": "Tag to release, created if missing",
                "required": True,
            },
            name={"type": "string", "description": "Release title"},
            body={"type": "string", "description": "Release notes (Markdown)"},
            target_commitish={"type": "string", "description": "Branch or SHA for a new tag"},
            prerelease={"type": "boolean"},
            generate_release_notes={"type": "boolean", "description": "Let GitHub write the notes"},
        ),
        required_scope="releases.write",
    ),
    ToolSpec(
        "publish_release",
        "Publish a draft release, making it public and notifying watchers.",
        ActionCategory.WRITE,
        _schema(owner=OWNER_PROP, repo=REPO_PROP, release_id=_RELEASE_ID_PROP),
        required_scope="releases.write",
        always_confirm=True,
    ),
    ToolSpec(
        "create_gist",
        "Create a gist with one file. Secret (unlisted) unless public is true.",
        ActionCategory.WRITE,
        _schema(
            filename={
                "type": "string",
                "description": "File name, like notes.md",
                "required": True,
            },
            content={"type": "string", "required": True},
            description={"type": "string"},
            public={"type": "boolean", "description": "Default false (secret gist)"},
        ),
        required_scope="gists.write",
        # A public gist is published to everyone.
        risk_check=risk.when_value(
            "public", lambda value: value is not False, "high", "it publishes a public gist"
        ),
    ),
)


def _release_summary(item: Any) -> dict[str, Any]:
    return {
        **scalars(
            item,
            "id",
            "tag_name",
            "name",
            "draft",
            "prerelease",
            "created_at",
            "published_at",
            "html_url",
        ),
        "author": login(item.get("author")) if isinstance(item, dict) else None,
    }


class ActivityMixin(GitHubApiBase):
    """Notification, release and gist actions."""

    async def list_notifications(
        self, include_read: Any = False, participating: Any = False, limit: Any = None
    ) -> list[dict[str, Any]]:
        per_page = clamp_limit(limit)
        params = {
            "all": "true"
            if include_read is not None and flag(include_read, "include_read")
            else "false",
            "participating": "true"
            if participating is not None and flag(participating, "participating")
            else "false",
            "per_page": per_page,
        }
        data = await self._get_json("/notifications", params=params)
        return [
            {
                **scalars(n, "id", "reason", "unread", "updated_at"),
                "repository": nested_str(n, "repository", "full_name", max_chars=200),
                "title": nested_str(n, "subject", "title"),
                "type": nested_str(n, "subject", "type", max_chars=50),
            }
            for n in as_list(data)[:per_page]
        ]

    async def list_releases(self, owner: str, repo: str, limit: Any = None) -> list[dict[str, Any]]:
        per_page = clamp_limit(limit)
        data = await self._get_json(
            f"{repo_path(owner, repo)}/releases", params={"per_page": per_page}
        )
        return [_release_summary(item) for item in as_list(data)[:per_page]]

    async def get_release(
        self, owner: str, repo: str, release_id: Any = None, tag: Optional[str] = None
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        if release_id is not None and tag is not None:
            raise ConnectorError("Pass release_id or tag, not both.")
        if release_id is not None:
            path = f"{base}/releases/{positive_int(release_id, 'release_id')}"
        elif tag is not None:
            path = f"{base}/releases/tags/{path_segment(git_ref(tag, 'tag'))}"
        else:
            path = f"{base}/releases/latest"
        data = as_object(await self._get_json(path))
        assets = nested(data, "assets")
        return {
            **_release_summary(data),
            **scalars(data, "target_commitish"),
            "assets": [
                scalars(a, "name", "size", "download_count", "browser_download_url")
                for a in as_list(assets if isinstance(assets, list) else [])[:20]
            ],
            **body_fields(
                data.get("body"),
                MAX_RELEASE_BODY_CHARS,
                f"Notes cut at {MAX_RELEASE_BODY_CHARS} characters; the full text is at html_url.",
            ),
        }

    async def mark_notification_read(
        self, thread_id: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        text = (
            str(thread_id).strip()
            if isinstance(thread_id, (str, int)) and not isinstance(thread_id, bool)
            else ""
        )
        if not _THREAD_ID_RE.fullmatch(text):
            raise ConnectorError("thread_id must be a notification thread id (digits).")
        require_confirmation(
            user_confirmed,
            "mark_notification_read",
            f"Mark GitHub notification thread {text} as read.",
        )
        await self._send_json("PATCH", f"/notifications/threads/{path_segment(text)}")
        return {"thread_id": text, "read": True}

    async def create_release(
        self,
        owner: str,
        repo: str,
        tag_name: str,
        name: Optional[str] = None,
        body: Optional[str] = None,
        target_commitish: Optional[str] = None,
        prerelease: Any = False,
        generate_release_notes: Any = False,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        payload: dict[str, Any] = {"tag_name": git_ref(tag_name, "tag_name"), "draft": True}
        if name is not None:
            payload["name"] = text_arg(name, "name", max_chars=256)
        if body is not None:
            payload["body"] = text_arg(body, "body", required=False)
        if target_commitish is not None:
            payload["target_commitish"] = git_ref(target_commitish, "target_commitish")
        if prerelease is not None:
            payload["prerelease"] = flag(prerelease, "prerelease")
        if generate_release_notes is not None:
            payload["generate_release_notes"] = flag(
                generate_release_notes, "generate_release_notes"
            )
        require_confirmation(
            user_confirmed,
            "create_release",
            f"Create a draft release for tag '{payload['tag_name']}' in {owner}/{repo} "
            "(it stays private until published; the tag is created if it does not exist).",
        )
        data = as_object(await self._send_json("POST", f"{base}/releases", json=payload))
        return _release_summary(data)

    async def publish_release(
        self, owner: str, repo: str, release_id: Any, *, user_confirmed: bool = False
    ) -> dict[str, Any]:
        base = repo_path(owner, repo)
        rid = positive_int(release_id, "release_id")
        require_confirmation(
            user_confirmed,
            "publish_release",
            f"Publish draft release {rid} in {owner}/{repo}: it becomes public and watchers are notified.",
        )
        data = as_object(
            await self._send_json("PATCH", f"{base}/releases/{rid}", json={"draft": False})
        )
        return _release_summary(data)

    async def create_gist(
        self,
        filename: str,
        content: str,
        description: Optional[str] = None,
        public: Any = False,
        *,
        user_confirmed: bool = False,
    ) -> dict[str, Any]:
        name = filename.strip() if isinstance(filename, str) else ""
        if not _GIST_FILENAME_RE.fullmatch(name) or name.startswith("gistfile"):
            raise ConnectorError("filename must be a plain file name like 'notes.md'.")
        text = text_arg(content, "content", max_chars=MAX_GIST_CHARS)
        about = text_arg(description, "description", required=False, max_chars=1000)
        is_public = flag(public, "public") if public is not None else False
        require_confirmation(
            user_confirmed,
            "create_gist",
            f"Create a {'PUBLIC' if is_public else 'secret'} gist '{name}' "
            f"({len(text or '')} characters){': ' + preview(about, 100) if about else ''}. "
            "Anyone with the link can read a secret gist.",
        )
        payload: dict[str, Any] = {"public": is_public, "files": {name: {"content": text}}}
        if about is not None:
            payload["description"] = about
        data = as_object(await self._send_json("POST", "/gists", json=payload))
        return {**scalars(data, "id", "html_url", "public", "created_at"), "filename": name}
