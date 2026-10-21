"""Tests for the texts built from a file check: services/file_reputation/verdicts.py
(``FileVerdict`` summaries, tool results, attachment entries, reason sentences, the upload card's
sentence) and alerts.py (the messages a person gets on Telegram or Slack). They prove no text
ever calls a file safe, a not-checked answer always says why, an upload is offered only for an
unknown file that has a byte source, VirusTotal's label and type are reduced to safe tokens, and
names in alerts and cards are defanged so Telegram draws no link from them.

Why it exists: S2, S3, the intake, the toolkit and the Security tab all print these texts; a
wording slip that says "safe" or leaks an outside string would reach every surface at once.
"""

from __future__ import annotations

import json
import unicodedata
from datetime import date
from pathlib import Path

from services.file_reputation.alerts import (
    KEY_REJECTED_ALERT,
    alert_name,
    analysis_done_alert,
    analysis_timeout_alert,
    flagged_alert,
)
from services.file_reputation.verdicts import (
    NOT_A_GUARANTEE,
    REASON_CODES,
    UPLOAD_HINT,
    FileVerdict,
    clean_file_type,
    clean_threat_label,
    reason_sentence,
    size_label,
    upload_card_sentence,
)
from tests.file_reputation.fakevt import sha_of

SHA = sha_of(b"some file")
DOT_LEADER = "․"


def every_verdict() -> list[FileVerdict]:
    checked = [
        FileVerdict(SHA, "malicious", malicious=41, suspicious=2, engines=72,
                    threat_label="trojan.emotet", file_type="Win32 EXE",
                    first_seen=date(2024, 3, 1), last_scanned=date(2026, 10, 10)),
        FileVerdict(SHA, "suspicious", malicious=1, suspicious=1, engines=70),
        FileVerdict(SHA, "no_detections", engines=68),
        FileVerdict(SHA, "unknown", can_upload=True),
    ]
    unchecked = [FileVerdict.not_checked(SHA, code) for code in REASON_CODES]
    unchecked.append(FileVerdict(SHA, "not_checked"))
    unchecked.append(FileVerdict(SHA, "not_checked", reason="something_new"))
    return checked + unchecked


def without_the_disclaimer(text: str) -> str:
    return text.replace(NOT_A_GUARANTEE, "")


def test_no_verdict_ever_reads_as_safe():
    for verdict in every_verdict():
        texts = [verdict.summary(), json.dumps(verdict.as_tool_result()),
                 json.dumps(verdict.as_entry())]
        for text in texts:
            # The only "safe" anywhere is inside "That is not a guarantee it is safe."
            assert "safe" not in without_the_disclaimer(text).lower(), text
        assert verdict.as_tool_result()["verdict"] in (
            "malicious", "suspicious", "no_detections", "unknown", "not_checked", "pending"
        )


def test_summaries_say_how_many_vendors_flag_a_file_and_nothing_more():
    malicious, suspicious, clean, unknown = every_verdict()[:4]

    assert malicious.summary() == (
        "VirusTotal: 41 of 72 security vendors flag this file as malicious and 2 more as "
        "suspicious (trojan.emotet)."
    )
    assert FileVerdict(SHA, "malicious", malicious=41, engines=72).summary() == (
        "VirusTotal: 41 of 72 security vendors flag this file as malicious."
    )
    assert suspicious.summary() == (
        "VirusTotal: 2 of 70 security vendors flag this file. A few detections can be false "
        "alarms, so treat it with care."
    )
    assert clean.summary() == (
        "VirusTotal: none of 68 security vendors flag this file. That is not a guarantee it is "
        "safe."
    )
    assert unknown.summary().startswith("VirusTotal has no record of this file")
    assert (malicious.flagged, suspicious.flagged, clean.flagged, unknown.flagged) == (
        True, True, False, False
    )
    assert (malicious.flagged_by, suspicious.flagged_by, clean.flagged_by) == (41, 2, 0)


def test_not_checked_answers_always_say_why_and_name_the_owners_limit_when_known():
    assert FileVerdict.not_checked(SHA, "no_key").summary() == (
        "Not checked: no VirusTotal key is set (the owner can add one in Security → Service "
        "keys)."
    )
    daily = FileVerdict.not_checked(SHA, "daily_limit", limit=500)
    assert daily.verdict == "not_checked"
    assert daily.summary() == "Not checked: today's 500 VirusTotal lookups are used up."
    assert FileVerdict.not_checked(SHA, "daily_limit").summary() == (
        "Not checked: today's VirusTotal lookups are used up."
    )
    minute = FileVerdict.not_checked(SHA, "minute_limit", limit=4)
    assert minute.verdict == "pending"
    assert minute.summary() == (
        "Not checked yet: VirusTotal's limit of 4 lookups a minute was reached; Crawler will "
        "check it shortly."
    )
    assert FileVerdict.not_checked(SHA, "virustotal_limit").verdict == "pending"
    assert reason_sentence("too_large") == "it is larger than 25 MB, too large to fingerprint"
    assert reason_sentence("user_limit", limit=100) == "your 100 lookups for today are used up"
    assert reason_sentence("automatic_limit", limit=100).startswith(
        "today's 100 automatic checks are used up"
    )
    # A limit is only named for the limit reasons, and never a nonsense one.
    assert reason_sentence("no_key", limit=500) == reason_sentence("no_key")
    assert reason_sentence("daily_limit", limit=True) == reason_sentence("daily_limit")
    assert reason_sentence("daily_limit", limit=0) == reason_sentence("daily_limit")
    # Unknown codes get a plain sentence, never the code.
    assert reason_sentence("internal_code_xyz") == "VirusTotal could not be asked"
    assert reason_sentence(None) == "VirusTotal could not be asked"
    for code in REASON_CODES:
        sentence = reason_sentence(code)
        assert sentence and not sentence.endswith(".") and "_" not in sentence


def test_tool_results_offer_an_upload_only_for_an_unknown_file_with_a_source():
    malicious = every_verdict()[0]

    assert malicious.as_tool_result() == {
        "ok": True,
        "sha256": SHA,
        "verdict": "malicious",
        "flagged_by": 41,
        "engines": 72,
        "threat_label": "trojan.emotet",
        "file_type": "Win32 EXE",
        "first_seen": "2024-03-01",
        "last_scanned": "2026-10-10",
        "summary": malicious.summary(),
        "can_upload": False,
    }
    with_source = FileVerdict(SHA, "unknown", can_upload=True).as_tool_result()
    without_source = FileVerdict(SHA, "unknown").as_tool_result()
    assert (with_source["can_upload"], with_source["upload_hint"]) == (True, UPLOAD_HINT)
    assert without_source["can_upload"] is False and "upload_hint" not in without_source
    # A known file is never offered, whatever the caller set.
    assert FileVerdict(SHA, "no_detections", engines=60, can_upload=True).as_tool_result()[
        "can_upload"
    ] is False
    pending = FileVerdict.not_checked(SHA, "minute_limit").as_tool_result()
    assert pending == {
        "ok": True,
        "sha256": SHA,
        "verdict": "pending",
        "reason": "minute_limit",
        "summary": pending["summary"],
        "can_upload": False,
    }


def test_attachment_entries_carry_facts_only():
    malicious = every_verdict()[0]

    assert malicious.as_entry() == {
        "verdict": "malicious", "flagged_by": 41, "engines": 72, "label": "trojan.emotet"
    }
    assert FileVerdict(SHA, "unknown").as_entry() == {
        "verdict": "unknown", "flagged_by": 0, "engines": 0, "label": None
    }


def test_threat_labels_and_file_types_are_reduced_to_safe_tokens():
    assert clean_threat_label("  Trojan.Emotet/Gen  ") == "trojan.emotet/gen"
    assert clean_threat_label("ransom:win32/lockbit-3") == "ransom:win32/lockbit-3"
    for bad in ("two words", "label\nnext", "a" * 65, "", "émotet", "<b>x</b>", None, 3):
        assert clean_threat_label(bad) is None
    assert clean_file_type("PE32 executable\t(GUI)\x00") == "PE32 executable (GUI)"
    assert clean_file_type("\u202e\u200b") is None
    assert clean_file_type("x" * 41) == "x" * 40
    assert clean_file_type(None) is None


def test_the_upload_card_names_the_file_its_size_and_that_virustotal_shares_uploads():
    sha = "3f2a9c1d" + "0" * 52 + "d41e"

    sentence = upload_card_sentence("setup.exe", 2_516_582, sha)

    assert sentence == (
        f'Send "setup{DOT_LEADER}exe" (2.4 MB, SHA-256 3f2a9c1d…d41e) to VirusTotal to be '
        "scanned. VirusTotal shares files it receives with security companies, and its paying "
        "users can download them: never send private documents."
    )
    assert upload_card_sentence("x", None, sha).startswith('Send "x" (SHA-256 3f2a9c1d…d41e)')
    assert "\\u0441" in upload_card_sentence("\u0441etup.exe", 10, sha)
    assert [size_label(n) for n in (0, 1, 512, 1024, 1536, 830 * 1024, 25 * 1024 * 1024)] == [
        "0 bytes", "1 byte", "512 bytes", "1 KB", "1.5 KB", "830 KB", "25 MB"
    ]
    assert size_label(None) is None and size_label(-1) is None and size_label(True) is None


def test_alert_names_are_defanged_so_telegram_draws_no_link():
    verdict = FileVerdict(SHA, "malicious", malicious=41, engines=72,
                          threat_label="trojan.win32/emotet")

    text = flagged_alert("invoice.pdf.zip", verdict)

    assert text == (
        f'⚠️ File check: VirusTotal flags "invoice{DOT_LEADER}pdf{DOT_LEADER}zip" as malicious: '
        f"41 of 72 security vendors (trojan{DOT_LEADER}win32∕emotet). Don't open it or send "
        "it on. Details: Security → File checks."
    )
    for link_like in ("invoice.pdf", "pdf.zip", "/", "@"):
        assert link_like not in text.replace("Security → File checks.", "")
    assert "@" not in alert_name("dana@example.com.zip")
    assert "." not in alert_name("evil.example.mov")


def test_alert_names_drop_direction_overrides_and_are_capped():
    assert alert_name("invoice\u202efdp.exe") == f"invoice fdp{DOT_LEADER}exe"
    assert alert_name("a\nb\tc\u2028d") == "a b c d"
    assert alert_name("") == "file" and alert_name(None) == "file"
    long = alert_name("n" * 300)
    assert len(long) == 120 and long.endswith("…")


def test_only_flagged_files_are_alerted_and_finished_scans_never_say_safe():
    suspicious = FileVerdict(SHA, "suspicious", malicious=0, suspicious=2, engines=70)
    clean = FileVerdict(SHA, "no_detections", engines=71)
    unknown = FileVerdict(SHA, "unknown")

    assert flagged_alert("report.docm", suspicious) == (
        f'⚠️ File check: 2 of 70 security vendors on VirusTotal flag "report{DOT_LEADER}docm". '
        "A few detections can be false alarms, so treat it with care. Details: Security → File "
        "checks."
    )
    for quiet in (clean, unknown, FileVerdict.not_checked(SHA, "daily_limit")):
        assert flagged_alert("x.exe", quiet) is None
    assert analysis_done_alert("setup.exe", clean) == (
        f'File check: VirusTotal finished scanning "setup{DOT_LEADER}exe": none of 71 security '
        "vendors flag it. That is not a guarantee it is safe."
    )
    assert analysis_done_alert("setup.exe", suspicious) == flagged_alert("setup.exe", suspicious)
    assert "could judge it" in analysis_done_alert("setup.exe", unknown)
    assert analysis_timeout_alert("setup.exe") == (
        f'File check: VirusTotal had not finished scanning "setup{DOT_LEADER}exe" after 15 '
        "minutes. Check it again later in Security → File checks."
    )
    for text in (analysis_done_alert("a", clean), analysis_done_alert("a", unknown),
                 analysis_timeout_alert("a"), KEY_REJECTED_ALERT):
        assert "safe" not in without_the_disclaimer(text).lower()


def _hidden_characters(text: str) -> list[str]:
    """Bidi controls, zero-width and other format characters, line and paragraph separators,
    private-use and unassigned code points, and control characters other than tab and newline:
    what an editor shows differently from what runs."""
    return [
        f"U+{ord(char):04X}"
        for char in text
        if unicodedata.category(char) in ("Cf", "Zl", "Zp", "Co", "Cn")
        or (unicodedata.category(char) == "Cc" and char not in "\t\n")
    ]


def test_no_file_reputation_source_or_test_file_holds_a_literal_bidi_or_invisible_character():
    # Trojan Source hygiene: such characters are written as \u escapes, so every file reads in
    # an editor or a review exactly as it runs (the rest of the codebase does the same).
    backend = Path(__file__).resolve().parents[2]
    files = sorted(
        [*(backend / "services" / "file_reputation").rglob("*.py"),
         *(backend / "tests" / "file_reputation").rglob("*.py")]
    )
    assert len(files) >= 18
    found = {}
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
            hidden = _hidden_characters(line)
            if hidden:
                found[f"{path.relative_to(backend).as_posix()}:{number}"] = hidden
    assert found == {}
    # The rule sees the characters this suite once held literally, and lets visible ones be.
    assert _hidden_characters('alert_name("invoice\u202efdp.exe")') == ["U+202E"]
    assert _hidden_characters("\u200b\ufeff\u2066\u2028\r") == [
        "U+200B", "U+FEFF", "U+2066", "U+2028", "U+000D"
    ]
    assert _hidden_characters("\u26a0\ufe0f File check \u2192 \u2024\u2215\t") == []


def test_a_stored_card_name_is_used_as_it_is_and_anything_else_reads_file():
    """The upload card's ``_upload`` name is ``card_name`` output; the sentence must not escape
    it a second time, and a stored name that is not such output (a tampered row) is not shown."""
    from services.file_reputation.verdicts import card_name, is_card_name, stored_card_sentence

    digest = sha_of(b"stored card")
    shown = card_name("\u0441etup.exe")
    assert is_card_name(shown) and shown == "\\u0441etup\u2024exe"
    assert stored_card_sentence(shown, 1024, digest) == upload_card_sentence("\u0441etup.exe", 1024, digest)
    for tampered in ("\u0441etup.exe", "x\u202eexe.pdf", "", None, 7, "a" * 400):
        assert is_card_name(tampered) is False
        assert stored_card_sentence(tampered, None, digest).startswith('Send "file" (SHA-256 ')
