"""Decides which files count as "risky" for file reputation: programs, scripts, archives, disk
images, macro-enabled Office files and the other types malware usually arrives as.

Why it exists: every file is looked up by its fingerprint, but only a risky one may be kept for a
possible upload to VirusTotal. A PDF, a plain Office document, a picture or a text file is a
personal document more often than not, and VirusTotal shares the files it receives with security
companies, so Crawler never holds such a file in memory, never keeps a re-fetchable Telegram
reference to it, and never lets a card proposed in chat send it (review SEC-F2; the owner can
still send one by picking it on the Security page). The same rule tells S2 which mail
attachments are worth a lookup at all.

Two signals, either one is enough: the leading bytes (a Windows, Linux or Mac program, a RAR,
7-Zip or gzip archive, a legacy OLE compound file such as a macro-carrying .doc or an .msi, or a
zip that is not a plain Office or e-book file), and the name's extension or the declared media
type (a generic zip type follows the same plain-Office exemption as the zip magic, because
senders often declare a .docx as application/zip). Without bytes (``head=None``) the name and
type decide alone; a renamed executable then reads as personal, which can only ever refuse an
upload, never allow one.

Pure: no I/O, no imports beyond the standard library.

Used by: services/file_reputation/service.py (intake: holding bytes and Telegram file ids) and
toolkit.py (the ``personal_document`` precheck), and S2's mail scan (``is_risky_attachment``).
"""

from __future__ import annotations

from typing import Optional

# How many leading bytes the magic checks need; callers may pass more.
HEAD_BYTES = 16

# Program, script, shortcut, installer, disk-image, archive, macro-enabled Office and
# active-content extensions (S10 4.10).
RISKY_EXTENSIONS: frozenset[str] = frozenset(
    {
        # programs, libraries and installers
        "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp",
        # scripts
        "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "sh",
        # shortcuts
        "lnk", "url",
        # disk images and packages
        "iso", "img", "vhd", "vhdx", "jar", "apk", "dmg", "pkg", "app",
        # archives
        "zip", "rar", "7z", "gz", "tgz", "cab",
        # macro-enabled Office files and add-ins
        "docm", "dotm", "xlsm", "xltm", "xlsb", "pptm", "potm", "ppam", "xlam",
        # active content
        "one", "svg", "htm", "html", "mht", "chm", "reg", "scf", "inf",
    }
)

# Zip containers that are ordinary documents: a zip magic with one of these extensions is not
# risky by its bytes (a .docx cannot carry macros; a .docm is caught by its extension).
OFFICE_ZIP_EXTENSIONS: frozenset[str] = frozenset(
    {"docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"}
)

# Declared media types of the same kinds. Parameters (";charset=...") and case are ignored.
RISKY_MEDIA_TYPES: frozenset[str] = frozenset(
    {
        # programs and installers
        "application/x-msdownload",
        "application/x-dosexec",
        "application/x-msdos-program",
        "application/vnd.microsoft.portable-executable",
        "application/x-executable",
        "application/x-elf",
        "application/x-mach-binary",
        "application/x-msi",
        "application/x-ms-installer",
        "application/x-ms-shortcut",
        "application/x-mswinurl",
        "application/internet-shortcut",
        # scripts
        "application/x-bat",
        "application/x-sh",
        "application/x-shellscript",
        "text/x-shellscript",
        "text/x-sh",
        "application/javascript",
        "application/x-javascript",
        "text/javascript",
        "application/vbscript",
        "text/vbscript",
        "application/hta",
        "application/x-powershell",
        # disk images and packages
        "application/x-iso9660-image",
        "application/x-apple-diskimage",
        "application/java-archive",
        "application/x-java-archive",
        "application/vnd.android.package-archive",
        # archives
        "application/zip",
        "application/x-zip-compressed",
        "application/vnd.rar",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/gzip",
        "application/x-gzip",
        "application/vnd.ms-cab-compressed",
        # macro-enabled Office files and add-ins
        "application/vnd.ms-word.document.macroenabled.12",
        "application/vnd.ms-word.template.macroenabled.12",
        "application/vnd.ms-excel.sheet.macroenabled.12",
        "application/vnd.ms-excel.template.macroenabled.12",
        "application/vnd.ms-excel.sheet.binary.macroenabled.12",
        "application/vnd.ms-excel.addin.macroenabled.12",
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
        "application/vnd.ms-powerpoint.template.macroenabled.12",
        "application/vnd.ms-powerpoint.addin.macroenabled.12",
        # active content
        "application/onenote",
        "image/svg+xml",
        "text/html",
        "application/xhtml+xml",
        "application/x-mimearchive",
        "application/vnd.ms-htmlhelp",
        "application/x-chm",
    }
)

# The generic zip media types. A .docx, .xlsx or .epub is a zip, and some mail clients and
# libmagic-based senders declare it as one of these, so they follow the same plain-Office
# exemption as the zip magic: otherwise every such personal document would be held for an upload
# and pass the personal_document precheck (review SEC-F2).
_ZIP_MEDIA_TYPES: frozenset[str] = frozenset({"application/zip", "application/x-zip-compressed"})

# Leading bytes of programs, archives and OLE compound files (S10 4.10). The Mach-O magics are
# feedface / feedfacf (big-endian), cefaedfe / cffaedfe (little-endian) and cafebabe (a
# universal binary; Java class files share it and are risky too).
_RISKY_MAGIC: tuple[bytes, ...] = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"Rar!",
    b"7z\xbc\xaf\x27\x1c",
    b"\x1f\x8b",
    b"\xd0\xcf\x11\xe0",
)
_ZIP_MAGIC = b"PK\x03\x04"


def _base_name(name: Optional[str]) -> str:
    # The last path component; trailing dots and spaces are ignored, because Windows ignores
    # them when it opens a file ("invoice.exe. " runs as an .exe).
    if not name:
        return ""
    return str(name).replace("\\", "/").rsplit("/", 1)[-1].rstrip(" .")


def _extension(base: str) -> str:
    _stem, dot, ext = base.rpartition(".")
    if not dot:
        return ""
    # A name that is only an extension (".exe") still runs as one on Windows.
    return ext.split(":", 1)[0].strip().lower()


def extension_of(name: Optional[str]) -> str:
    """The lowercased extension of *name* without its dot ("" when there is none).

    Only the last path component counts, and trailing dots and spaces are ignored. Matching is
    by code point, so a right-to-left override that makes "fdp.exe" display as "exe.pdf"
    changes nothing here.
    """
    return _extension(_base_name(name))


def _extensions(name: Optional[str]) -> tuple[str, ...]:
    """The extension of *name*, plus, when it has a colon, the extension before the colon: an
    NTFS stream name ("invoice.exe:Zone.Identifier") opens the file before it."""
    base = _base_name(name)
    found = [_extension(base)]
    if ":" in base:
        found.append(_extension(base.split(":", 1)[0].rstrip(" .")))
    return tuple(ext for ext in found if ext)


def _media_type(media_type: Optional[str]) -> str:
    if not media_type:
        return ""
    return str(media_type).split(";", 1)[0].strip().lower()


def risky_by_head(head: Optional[bytes], name: Optional[str] = None) -> bool:
    """True when the leading bytes are a program, an archive or an OLE compound file. A zip is
    risky unless *name* has a plain Office or e-book extension."""
    if not head:
        return False
    if head.startswith(_RISKY_MAGIC):
        return True
    if head.startswith(_ZIP_MAGIC):
        return extension_of(name) not in OFFICE_ZIP_EXTENSIONS
    return False


def risky_by_media_type(media_type: Optional[str], name: Optional[str] = None) -> bool:
    """True when the declared media type is a program, script, archive or active-content type.
    A generic zip type is risky unless *name* has a plain Office or e-book extension, the same
    rule as the zip magic in ``risky_by_head``."""
    declared = _media_type(media_type)
    if declared not in RISKY_MEDIA_TYPES:
        return False
    if declared in _ZIP_MEDIA_TYPES:
        return extension_of(name) not in OFFICE_ZIP_EXTENSIONS
    return True


def is_risky(name: Optional[str], media_type: Optional[str], head: Optional[bytes] = None) -> bool:
    """True when the file is of a kind malware usually arrives as: by its leading bytes (when
    given), its name's extension, or its declared media type. A plain Office or e-book name
    exempts only a zip (by magic or by a generic zip type), never other risky bytes or types."""
    if risky_by_head(head, name):
        return True
    if any(ext in RISKY_EXTENSIONS for ext in _extensions(name)):
        return True
    return risky_by_media_type(media_type, name)


def is_risky_attachment(name: Optional[str], media_type: Optional[str]) -> bool:
    """S2's question for a mail attachment it has not downloaded: the name and the declared
    type alone (``is_risky`` without bytes)."""
    return is_risky(name, media_type, None)
