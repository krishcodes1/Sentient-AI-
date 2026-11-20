"""The backend serving the built frontend (FRONTEND_DIST), as the native Mac app runs it.

Why it exists: on a Mac the desktop app has no nginx and no Node, so the backend answers
both the SPA and /api on one origin. These tests pin the contract: real files as they are,
every other page path is index.html, and /api is never answered with the page.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from main import mount_frontend


def _client(tmp_path) -> TestClient:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><title>Crawler AI</title>")
    (tmp_path / "assets" / "app.js").write_text("console.log('hi')")
    app = FastAPI()

    @app.get("/api/ping")
    async def ping() -> dict[str, str]:
        return {"pong": "yes"}

    mount_frontend(app, str(tmp_path))
    return TestClient(app)


def test_root_and_app_routes_are_the_spa(tmp_path) -> None:
    client = _client(tmp_path)
    for path in ("/", "/settings/profile", "/chat/123"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        assert "text/html" in resp.headers["content-type"]
        assert "<title>Crawler AI</title>" in resp.text


def test_real_files_are_served(tmp_path) -> None:
    resp = _client(tmp_path).get("/assets/app.js")
    assert resp.status_code == 200
    assert resp.text == "console.log('hi')"


def test_api_is_never_the_page(tmp_path) -> None:
    client = _client(tmp_path)
    assert client.get("/api/ping").json() == {"pong": "yes"}
    for path in ("/api/nope", "/api"):
        resp = client.get(path)
        assert resp.status_code == 404, path
        assert "Crawler AI</title>" not in resp.text


def test_no_escape_from_the_dist(tmp_path) -> None:
    (tmp_path.parent / "secret.txt").write_text("nope")
    resp = _client(tmp_path).get("/../secret.txt")
    assert "nope" not in resp.text
