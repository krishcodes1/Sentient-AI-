"""The video.* built-in family: transcripts of YouTube videos, lecture pages,
podcast episodes and caption files, cached per user.

Why it exists: it groups the family's modules. toolkit.py is the entry point
the tool registry dispatches to; sources.py holds the links and the YouTube
host rule (stdlib only, so web.py imports it); captions.py, podcast.py and
page.py read publisher text; provider_video.py reads YouTube through the
turn's own Gemini; store.py is the per-user cache; facts.py is what the
audit keeps. Nothing is imported here, so importing one light module does
not pull in the database models.
"""
