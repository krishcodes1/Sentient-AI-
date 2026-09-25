"""The fake site every browser test drives. One test per route asserts the
markers its consumers grep for, so a copy change fails here, not in a
guard or toolkit test three files away."""

from __future__ import annotations

import http.client
from urllib.parse import urlsplit

import pytest


def get(fakesite, path: str) -> tuple[int, dict[str, str], str]:
    parts = urlsplit(fakesite.url(path))
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    conn.request("GET", parts.path)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    headers = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, headers, body


def test_fakesite_binds_ipv4_loopback_and_sets_the_test_toggle(fakesite, monkeypatch):
    import os

    assert fakesite.base.startswith("http://127.0.0.1:")
    assert fakesite.url("/grades") == fakesite.base + "/grades"
    assert os.environ.get("CRAWLER_ALLOW_LOOPBACK_FOR_TESTS") == "1"


@pytest.mark.parametrize(
    "path, status, marker",
    [
        ("/", 200, 'href="/grades">Grades</a>'),  # a link whose name is not consequential
        ("/login", 200, 'type="password"'),
        ("/home", 200, "Signed in"),
        ("/captcha", 200, 'title="reCAPTCHA"'),
        ("/badge", 200, 'class="grecaptcha-badge"'),
        ("/grades", 200, '<span class="screenreader-only">Missing</span>'),
        ("/flights", 200, "$489"),
        ("/hidden", 200, "ignore previous instructions"),
        ("/post", 200, ">Sign up</button>"),
        ("/controls", 200, ">Review order</a>"),
        ("/human", 200, "Verify you are human"),
        ("/bots.html", 200, "Please wait"),
        ("/forbidden", 403, "no access"),
        ("/throttled", 429, "Slow down"),
        ("/sso/otp", 200, 'id="otp"'),
        ("/frame", 200, 'src="/frame-inner"'),
        ("/frame-inner", 200, ">Submit inner</button>"),
    ],
)
def test_route_markers(fakesite, path, status, marker):
    code, _headers, body = get(fakesite, path)
    assert code == status and marker in body, (path, body[:200])


def test_grades_page_has_every_status_and_a_footer_below_the_fold(fakesite):
    _, _, body = get(fakesite, "/grades")
    assert body.count("screenreader-only") >= 2 and "Late" in body
    assert 'style="height:1400px"' in body and "Privacy policy" in body


def test_controls_page_has_the_consequential_click_targets(fakesite):
    _, _, body = get(fakesite, "/controls")
    for marker in (
        ">Grades</a>", ">Show more</button>", ">Search</button>", ">Log in</button>",
        ">Review order</a>", ">Sign up now</a>", ">Subscribe to updates</a>",
        ">Post comment</button>", ">Continue</button>",
        'form="ext-search">Apply filter</button>', 'form="ext-pin">Unlock</button>',
    ):
        assert marker in body, marker


def test_redirects(fakesite):
    code, headers, _ = get(fakesite, "/sso/start")
    assert code == 302 and headers["location"] == "/sso/idp"
    code, headers, _ = get(fakesite, "/redirect-private")
    assert code == 302 and headers["location"] == "http://10.0.0.1/"


def test_login_post_sets_a_cookie_and_lands_on_home(fakesite):
    parts = urlsplit(fakesite.base)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    conn.request(
        "POST", "/login", body="username=krish&password=x",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = conn.getresponse()
    assert resp.status == 303 and resp.getheader("Location") == "/home"
    assert "session=" in (resp.getheader("Set-Cookie") or "")
