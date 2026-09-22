import json

import httpx
import pytest
from fastapi.testclient import TestClient

from login_app.app import Settings, create_app
from login_app.users import UserStore

SECRET = "proxy-secret"


class FakeAbuseApi:
    def __init__(self, decision="allow"):
        self.decision = decision
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.decision is None:
            return httpx.Response(503)
        return httpx.Response(200, json={"decision": self.decision, "reason": "test"})

    @property
    def last_event(self):
        return json.loads(self.calls[-1].content)


@pytest.fixture
def api():
    return FakeAbuseApi()


@pytest.fixture
def client(api):
    settings = Settings(abuse_api_url="http://abuse", abuse_api_token="tok", proxy_shared_secret=SECRET,
                        session_secret="s", secure_cookies=False)
    app = create_app(settings, UserStore({"alice": "wonderland"}), transport=httpx.MockTransport(api))
    with TestClient(app, follow_redirects=False) as c:
        yield c


def login(client, password="wonderland", headers=None):
    return client.post("/login", data={"username": "alice", "password": password}, headers=headers or {})


def test_login_page(client):
    r = client.get("/login")
    assert r.status_code == 200 and 'name="password"' in r.text


def test_success_redirects_and_sets_session(client, api):
    r = login(client)
    assert r.status_code == 302 and r.headers["location"] == "/success"
    assert api.last_event["outcome"] == "success"
    assert api.calls[-1].url.path == "/v2/loginCheck"
    assert api.calls[-1].headers["authorization"] == "Bearer tok"
    assert "Welcome, alice" in client.get("/success").text


def test_success_requires_session(client):
    r = client.get("/success")
    assert r.status_code == 302 and r.headers["location"] == "/login"
    client.cookies.set("session", "YWxpY2U=|9999999999|forged")
    assert client.get("/success").status_code == 302


def test_bad_password_reported_as_fail(client, api):
    r = login(client, password="nope")
    assert r.status_code == 401
    assert api.last_event["outcome"] == "fail"


@pytest.mark.parametrize("decision,code", [("deny", 403), ("step-up", 401)])
def test_non_allow_decisions_block_session(client, api, decision, code):
    api.decision = decision
    r = login(client)
    assert r.status_code == code
    assert "session" not in r.cookies


def test_abuse_api_outage_fails_safe(client, api):
    api.decision = None
    r = login(client)
    assert r.status_code == 401 and "Additional verification" in r.text


def test_forwards_proxy_headers_and_trusts_xff_only_from_proxy(client, api):
    login(client, headers={"x-huginn-proxy-secret": SECRET, "x-tls-ja4": "t13d1516h2_a_b",
                           "x-forwarded-for": "198.51.100.4"})
    forwarded = api.calls[-1].headers
    assert forwarded["x-tls-ja4"] == "t13d1516h2_a_b"
    assert forwarded["x-huginn-proxy-secret"] == SECRET
    assert api.last_event["ip"] == "198.51.100.4"

    login(client, headers={"x-forwarded-for": "198.51.100.4"})
    assert api.last_event["ip"] != "198.51.100.4"
