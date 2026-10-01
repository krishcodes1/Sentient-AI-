"""Checks an image file with Pillow and reports it as a scanned page.

Why it exists: a photo of a handout is a document with no text layer. Pillow
(the only C parser in the worker) opens it with MAX_IMAGE_PIXELS at 40
million and the decompression-bomb warning raised as an error, so an image
that would expand to gigabytes is refused (``image_too_large``) before it is
decoded. Without a local OCR engine (phase 4) the page is reported as
unread, and the parent says so plainly instead of guessing.
"""

from __future__ import annotations

import io
import warnings
from typing import Any

from services.files.limits import MAX_IMAGE_PIXELS
from services.files.worker.protocol import Emitter, ParseError


def open_checked(data: bytes) -> Any:
    """The image in *data*, opened and verified under the pixel limit.
    Raises ParseError(image_too_large or corrupt)."""
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            image = Image.open(io.BytesIO(data))
            image.verify()
        except (Image.DecompressionBombError, Image.DecompressionBombWarning):
            raise ParseError("image_too_large") from None
        except Exception:  # noqa: BLE001 - any decoder failure is a damaged file
            raise ParseError("corrupt") from None
    return image


def parse(data: bytes, header: dict[str, Any], emit: Emitter) -> None:
    open_checked(data)
    emit.meta(title="", pages_total=1)
    emit.scan(1)
    emit.done(truncated=False)
