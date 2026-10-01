"""Downloads a file a person sent the Telegram bot (a document, a photo, and
later voice notes), bounded, from api.telegram.org only.

Why it exists: Telegram hands the bot a file_id; getFile turns it into a
file_path, and the bytes live at https://api.telegram.org/file/bot<token>/
<file_path>. That URL holds the bot token, so it is never logged, and no
exception text that could quote it is either (only the exception's type).
The file_path comes from Telegram's answer, so it is checked against a
strict pattern (no "..") before it is put in the URL, and the download is
streamed and abandoned past the byte cap (the Bot API serves files up to
20 MB). Shared by the document intake (telegram.py) and, later, voice notes.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

API_ROOT = "https://api.telegram.org"
# The Bot API's own getFile limit.
TELEGRAM_MAX_FILE_BYTES = 20 * 1024 * 1024

_FILE_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]{1,256}$")


class TelegramFileError(Exception):
    """A download that did not happen. ``code``: too_large, bad_path or
    download_failed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def valid_file_path(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _FILE_PATH_RE.fullmatch(value) is not None
        and ".." not in value
        and not value.startswith("/")
    )


async def download_telegram_file(
    client: httpx.AsyncClient, token: str, file_id: str, *, max_bytes: int
) -> bytes:
    """The bytes of Telegram file *file_id*, at most *max_bytes*. Raises
    TelegramFileError: ``too_large`` (Telegram's declared size or the
    stream passed the cap), ``bad_path`` (getFile answered a path that is
    not a plain relative one) or ``download_failed``."""
    try:
        response = await client.post(f"{API_ROOT}/bot{token}/getFile", json={"file_id": file_id})
        data = response.json()
    except Exception as exc:  # the type only: a message can quote the URL
        logger.warning("telegram_get_file_failed", error_type=type(exc).__name__)
        raise TelegramFileError("download_failed") from None
    if not isinstance(data, dict) or not data.get("ok") or not isinstance(data.get("result"), dict):
        # Telegram refuses getFile for files over 20 MB ("file is too big").
        description = str(data.get("description", "")).lower() if isinstance(data, dict) else ""
        if "too big" in description:
            raise TelegramFileError("too_large")
        logger.warning("telegram_get_file_refused", code=data.get("error_code") if isinstance(data, dict) else None)
        raise TelegramFileError("download_failed")
    result = data["result"]
    size = result.get("file_size")
    if isinstance(size, int) and not isinstance(size, bool) and size > max_bytes:
        raise TelegramFileError("too_large")
    file_path = result.get("file_path")
    if not valid_file_path(file_path):
        logger.warning("telegram_file_path_refused")
        raise TelegramFileError("bad_path")
    url = f"{API_ROOT}/file/bot{token}/{file_path}"
    chunks = bytearray()
    try:
        async with client.stream("GET", url) as stream:
            if stream.status_code != 200:
                logger.warning("telegram_file_download_status", status=stream.status_code)
                raise TelegramFileError("download_failed")
            async for chunk in stream.aiter_bytes():
                chunks += chunk
                if len(chunks) > max_bytes:
                    raise TelegramFileError("too_large")
    except TelegramFileError:
        raise
    except Exception as exc:  # the type only: a message can quote the URL
        logger.warning("telegram_file_download_failed", error_type=type(exc).__name__)
        raise TelegramFileError("download_failed") from None
    return bytes(chunks)
