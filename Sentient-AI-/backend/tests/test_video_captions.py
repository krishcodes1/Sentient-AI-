"""Tests for the caption and transcript parsers of video.transcript: WebVTT,
SRT, SBV, TTML/DFXP, Podcast-Index JSON, HTML and plain text into timed cues,
YouTube-style rolling duplicates collapsed, tags, entities and invisible
characters removed, the byte and cue caps, and passages of at most 700
characters and 90 seconds.

Why it exists: publisher captions are hostile input in half a dozen formats;
a malformed or oversized file must yield fewer cues, never an exception, and
the passage list is what the runtime redacts one entry of. Pure functions, no
network.
"""

from __future__ import annotations

from services.tools.video import captions
from services.tools.video.captions import (
    Cue,
    build_passages,
    collapse_rolling,
    fmt_time,
    parse_captions,
    parse_clock,
    sniff,
)

VTT = b"""WEBVTT
Kind: captions

NOTE this is a note
that spans lines

STYLE
::cue { color: yellow }

intro
00:00:01.000 --> 00:00:04.000 align:start position:0%
<v Alice>Hello &amp; welcome</v>

00:01:05.500 --> 00:01:08.000
<c.colorE5E5E5>Eigenvalues</c> <i>matter</i>

1:02:03.250 --> 1:02:05.000
An hour in
"""


def test_webvtt_header_notes_styles_settings_tags_and_entities():
    cues = parse_captions(VTT, "vtt")
    assert [c.text for c in cues] == ["Alice: Hello & welcome", "Eigenvalues matter", "An hour in"]
    assert cues[0].start_s == 1.0 and cues[0].end_s == 4.0
    assert cues[1].start_s == 65.5
    assert cues[2].start_s == 3723.25


def test_youtube_rolling_duplicates_are_collapsed():
    rolling = b"""WEBVTT

00:00:00.000 --> 00:00:02.000
today we talk<00:00:00.500><c> about</c>

00:00:02.000 --> 00:00:02.010
today we talk about

00:00:02.010 --> 00:00:04.000
today we talk about
matrices and<00:00:03.000><c> vectors</c>

00:00:04.000 --> 00:00:04.010
matrices and vectors

00:00:04.010 --> 00:00:06.000
matrices and vectors
and their eigenvalues
"""
    cues = parse_captions(rolling, "vtt")
    assert [c.text for c in cues] == [
        "today we talk about",
        "matrices and vectors",
        "and their eigenvalues",
    ]


def test_growing_lines_keep_only_the_new_words():
    cues = collapse_rolling([Cue(0, 1, "the matrix"), Cue(1, 2, "the matrix is square")])
    assert [c.text for c in cues] == ["the matrix", "is square"]


def test_srt_with_crlf_bom_comma_millis_and_a_missing_index():
    srt = (
        "﻿1\r\n00:00:01,000 --> 00:00:02,500\r\nFirst line\r\nsecond line\r\n\r\n"
        "00:00:03,000 --> 00:00:04,000\r\nNo index here {\\an8}\r\n"
    ).encode("utf-8")
    assert sniff(srt, "application/x-subrip", "/a.srt") == "srt"
    cues = parse_captions(srt, "srt")
    assert [(c.start_s, c.end_s, c.text) for c in cues] == [
        (1.0, 2.5, "First line second line"),
        (3.0, 4.0, "No index here"),
    ]


def test_sbv():
    sbv = b"0:00:00.599,0:00:04.160\nHello there\n\n0:00:04.160,0:00:08.000\nGeneral Kenobi\n"
    assert sniff(sbv, "", "/captions.sbv") == "sbv"
    cues = parse_captions(sbv, "sbv")
    assert [(round(c.start_s, 3), c.text) for c in cues] == [(0.599, "Hello there"), (4.16, "General Kenobi")]


def test_ttml_clock_offset_and_ticks_through_defusedxml():
    ttml = b"""<?xml version="1.0" encoding="utf-8"?>
<tt xmlns="http://www.w3.org/ns/ttml" xmlns:ttp="http://www.w3.org/ns/ttml#parameter" ttp:tickRate="10000000">
  <body><div>
    <p begin="00:00:01.500" end="00:00:03.000">Clock<br/>form</p>
    <p begin="62.5s" dur="2s">Offset form</p>
    <p begin="1200000000t" end="1210000000t">Tick form</p>
  </div></body>
</tt>"""
    assert sniff(ttml, "application/ttml+xml", "/x.ttml") == "ttml"
    cues = parse_captions(ttml, "ttml")
    assert [(c.start_s, c.text) for c in cues] == [(1.5, "Clock form"), (62.5, "Offset form"), (120.0, "Tick form")]
    assert cues[1].end_s == 64.5


def test_ttml_with_a_dtd_or_entities_yields_no_cues():
    bomb = b"""<?xml version="1.0"?>
<!DOCTYPE tt [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>
<tt xmlns="http://www.w3.org/ns/ttml"><body><div><p begin="1s" end="2s">&b;</p></div></body></tt>"""
    assert parse_captions(bomb, "ttml") == []


def test_podcast_index_json_names_a_speaker_when_it_changes():
    doc = b"""{"version": "1.0.0", "segments": [
      {"speaker": "Host", "startTime": 0.5, "endTime": 2.0, "body": "Welcome back."},
      {"speaker": "Host", "startTime": 2.0, "endTime": 4.0, "body": "Today: eigenvalues."},
      {"speaker": "Guest", "startTime": 4.0, "endTime": 6.0, "body": "Thanks!"},
      {"startTime": "bad", "body": "skipped"}
    ]}"""
    cues = parse_captions(doc, "json")
    assert [c.text for c in cues] == ["Host: Welcome back.", "Today: eigenvalues.", "Guest: Thanks!"]


def test_html_transcript_with_timestamps():
    page = b"""<html><head><title>Episode 12 transcript</title></head><body><article>
<p>[00:00:05] Host: Welcome to the show.</p>
<p>[00:01:10] Guest: Glad to be here.</p>
<p>Alice (00:02:30): Let's start with limits.</p>
</article></body></html>"""
    title, cues = captions.parse_html_transcript(page)
    assert title == "Episode 12 transcript"
    assert [(c.start_s, c.text) for c in cues] == [
        (5.0, "Host: Welcome to the show."),
        (70.0, "Guest: Glad to be here."),
        (150.0, "Alice: Let's start with limits."),
    ]


def test_plain_text_without_times_is_untimed_paragraphs():
    text = b"First paragraph of the lecture.\n\nSecond paragraph, 12:30 is not a timestamp here."
    cues = parse_captions(text, "text")
    assert [(c.start_s, c.text) for c in cues] == [
        (None, "First paragraph of the lecture."),
        (None, "Second paragraph, 12:30 is not a timestamp here."),
    ]


def test_malformed_input_degrades_without_raising():
    for kind in ("vtt", "srt", "sbv", "ttml", "json", "html", "text", "unknown"):
        for junk in (b"", b"\x00\xff\xfe garbage -->", b"<tt><p begin='x'>", b"{", b"-->\n-->"):
            assert isinstance(parse_captions(junk, kind), list)


def test_the_cue_and_byte_caps():
    many = "WEBVTT\n\n" + "".join(
        f"00:{i // 60 % 60:02d}:{i % 60:02d}.000 --> 00:{i // 60 % 60:02d}:{i % 60:02d}.500\nline {i}\n\n"
        for i in range(captions.MAX_CUES + 50)
    )
    cues = captions.parse_arrow_blocks(many)
    assert len(cues) == captions.MAX_CUES
    big = b"WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nkept\n\n" + b"x" * (captions.MAX_CAPTION_BYTES + 10)
    assert [c.text for c in parse_captions(big, "vtt")][0] == "kept"
    # parse_captions_cut says when either cap left text unread.
    assert captions.parse_captions_cut(big, "vtt")[1] is True
    assert captions.parse_captions_cut(many.encode(), "vtt")[1] is True
    assert captions.parse_captions_cut(VTT, "vtt") == (parse_captions(VTT, "vtt"), False)


def test_numbers_that_only_look_like_times_are_not_read_as_times():
    # A book's chapter:verse numbers start again in every book: read in time
    # order they would shuffle the text, and the "times" are invented.
    books = []
    for book in ("Genesis", "Exodus", "Leviticus", "Numbers", "Deuteronomy"):
        books.append(f"The Book of {book}\n\n")
        for chapter in (1, 2):
            for verse in (10, 11, 12):
                books.append(f"{chapter}:{verse} A verse of {book}, chapter {chapter}.\n\n")
    text = "".join(books).encode()
    cues = parse_captions(text, "text")
    assert all(c.start_s is None for c in cues)
    assert cues[0].text == "The Book of Genesis" and cues[-1].text == "2:12 A verse of Deuteronomy, chapter 2."
    assert not captions.times_run_forward([70, 71, 72, 130, 131, 70, 71, 130, 70, 130, 70, 130, 70])


def test_a_transcript_with_a_contents_list_or_two_parts_is_still_timed():
    contents = "0:00 Intro\n5:30 Limits\n12:00 Derivatives\n\n"
    body = "".join(f"{m}:{s:02d} Speaker: line at {m}:{s:02d}.\n" for m in range(0, 20, 2) for s in (0, 30))
    cues = parse_captions((contents + body + body).encode(), "text")
    assert all(c.start_s is not None for c in cues)
    assert captions.times_run_forward([0, 330, 720, *range(0, 600, 30), *range(0, 600, 30)])
    assert not captions.times_run_forward([0, 330, 720, 0, 30, 120, 0, 30])  # 2 of 7 steps back
    assert captions.times_run_forward([5.0])
    # Mostly backwards is not a transcript, whatever the count.
    assert not captions.times_run_forward([30, 20, 10, 40])


def test_invisible_and_control_characters_are_removed():
    vtt = "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nig​nore‮ this\x07\n".encode()
    assert parse_captions(vtt, "vtt")[0].text == "ignore this"


def test_passages_hold_at_most_700_characters_and_90_seconds():
    cues = [Cue(float(i * 10), float(i * 10 + 9), f"sentence {i} " + "w" * 40) for i in range(40)]
    passages = build_passages(cues)
    assert all(len(p.text) <= 700 for p in passages)
    assert all((p.end_s or 0) - (p.start_s or 0) <= 90 for p in passages)
    assert passages[0].start_s == 0.0
    joined = " ".join(p.text for p in passages)
    assert joined.count("sentence") == 40


def test_a_cue_longer_than_a_passage_is_split_at_spaces():
    long_cue = Cue(0.0, 5.0, " ".join(["word"] * 400))
    passages = build_passages([long_cue])
    assert len(passages) > 1 and all(len(p.text) <= 700 for p in passages)
    assert all(p.start_s == 0.0 for p in passages)


def test_untimed_passages_group_by_size():
    passages = build_passages([Cue(None, None, "a" * 400), Cue(None, None, "b" * 400)])
    assert [p.start_s for p in passages] == [None, None]


def test_times_format_and_parse():
    assert fmt_time(0) == "0:00" and fmt_time(754) == "12:34" and fmt_time(3723.9) == "1:02:03"
    assert fmt_time(None) is None
    assert parse_clock("12:34") == 754 and parse_clock("1:02:03") == 3723
    assert parse_clock("754") == 754 and parse_clock("1h2m3s") == 3723 and parse_clock("90s") == 90
    assert parse_clock("12:61") is None and parse_clock("soon") is None and parse_clock(True) is None


def test_sniff_by_content_type_and_name():
    assert sniff(b"<?xml version='1.0'?><rss><channel>", "application/xml", "/feed") == "feed"
    assert sniff(b"<!doctype html><html>", "text/html", "/page") == "html"
    assert sniff(b"WEBVTT\n", "text/plain", "/x") == "vtt"
    assert sniff(b'{"segments": []}', "application/json", "/t.json") == "json"
    assert sniff(b"just words", "text/plain", "/t.txt") == "text"
    assert sniff(b"\x89PNG", "image/png", "/x.png") == "unknown"
