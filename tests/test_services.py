import hashlib
import hmac
import sys
import time
from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from abuse_api import main as api  # noqa: E402
from login_app import main as web  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_redis(monkeypatch):
    monkeypatch.setattr(api, "r", fakeredis.FakeRedis(decode_responses=True))


api_client = TestClient(api.app)


def ev(user="alice", ip="10.0.0.1", ua="Mozilla/5.0", ok=False, ts=None):
    return {"username": user, "ip": ip, "user_agent": ua,
            "timestamp": ts or time.time(), "success": ok}


def signed(ja4, ts=None, key=api.PROXY_HMAC_KEY):
    ts = str(ts or time.time())
    sig = hmac.new(key, f"{ja4}|{ts}".encode(), hashlib.sha256).hexdigest()
    return {"x-ja4": ja4, "x-ja4-ts": ts, "x-ja4-sig": sig}


def v1(**kw):
    return api_client.post("/v1/loginCheck", json=ev(**kw)).json()


def v2(headers=None, **kw):
    return api_client.post("/v2/loginCheck", json=ev(**kw), headers=headers or {}).json()


# ---------- v1 ----------
def test_clean_login_allowed():
    assert v1(ok=True) == {"verdict": "allow", "reason": "no_risk_signal"}


def test_automation_ua_denied():
    assert v1(ua="python-requests/2.31")["reason"] == "automation_ua"


def test_ip_elevated_then_burst():
    for _ in range(4):
        v1(user="x")
    assert v1(user="x")["reason"] == "ip_elevated"  # 5th failure
    for _ in range(14):
        v1(user="x")
    assert v1(user="x") == {"verdict": "deny", "reason": "ip_burst"}  # 20th


def test_low_and_slow_spray_caught_by_distinct_usernames(monkeypatch):
    # One attempt every 6 minutes: never trips the 5-minute burst rules,
    # but 10 distinct usernames inside 60 minutes trips the long window.
    clock = [time.time()]
    monkeypatch.setattr(api.time, "time", lambda: clock[0])
    for i in range(9):
        assert v1(user=f"user{i}", ts=clock[0])["verdict"] == "allow"
        clock[0] += 360
    assert v1(user="user9", ts=clock[0]) == {"verdict": "deny", "reason": "ip_spray"}


def test_success_after_failures_steps_up():
    for i in range(3):
        v1(user="bob", ip=f"10.0.1.{i}")
    assert v1(user="bob", ip="10.0.2.1", ok=True)["reason"] == "success_after_failures"


def test_clock_skew():
    assert v1(ok=True, ts=time.time() - 3600)["reason"] == "clock_skew"


# ---------- v2 trust boundary ----------
def test_unsigned_fingerprint_ignored():
    out = v2(headers={"x-ja4": "t13d_fake"}, ok=True)
    assert out["reason"].endswith("fingerprint_untrusted")


def test_forged_signature_ignored():
    out = v2(headers=signed("t13d_fake", key=b"attacker-guess"), ok=True)
    assert out["reason"].endswith("fingerprint_untrusted")


def test_stale_signature_ignored():
    out = v2(headers=signed("t13d_x", ts=time.time() - 120), ok=True)
    assert out["reason"].endswith("fingerprint_untrusted")


def test_valid_signature_trusted():
    assert v2(headers=signed("t13d_chrome"), ok=True) == {"verdict": "allow", "reason": "no_risk_signal"}


# ---------- v2 fingerprint rules ----------
def test_credential_stuffing_shared_ja4():
    for i in range(19):
        v2(headers=signed("t13d_bot"), user=f"u{i}", ip=f"10.9.{i}.1")
    out = v2(headers=signed("t13d_bot"), user="u19", ip="10.9.19.1")
    assert out == {"verdict": "deny", "reason": "ja4_shared_failures"}


def test_fingerprint_evasion_caught_by_ip():
    v2(headers=signed("ja4_a"), user="victim")  # one failure
    v2(headers=signed("ja4_b"), user="victim2")
    out = v2(headers=signed("ja4_c"), user="victim3")
    assert out == {"verdict": "deny", "reason": "ja4_rotation_with_failures"}


def test_denylisted_ja4(monkeypatch):
    monkeypatch.setattr(api, "JA4_DENYLIST", {"t13d_evil"})
    assert v2(headers=signed("t13d_evil"), ok=True)["reason"] == "ja4_denylist"


def test_new_ja4_for_known_user_steps_up():
    v2(headers=signed("ja4_home"), ok=True)
    out = v2(headers=signed("ja4_new"), ip="10.0.0.2", ok=True)
    assert out == {"verdict": "step_up", "reason": "ja4_new_for_user"}


# ---------- Login Web App end to end ----------
@pytest.fixture
def web_client(monkeypatch):
    def fake_post(url, json, headers, timeout):
        path = url.split("8001", 1)[1]
        resp = api_client.post(path, json=json, headers=headers)
        resp.raise_for_status = lambda: None
        return resp
    monkeypatch.setattr(web.httpx, "post", fake_post)
    return TestClient(web.app)


def test_get_login_page(web_client):
    assert "Sign in" in web_client.get("/login").text


def test_good_login_redirects_302(web_client):
    resp = web_client.post("/login", data={"username": "alice", "password": "correct horse"},
                           headers=signed("t13d_chrome"), follow_redirects=False)
    assert resp.status_code == 302 and resp.headers["location"] == "/success"


def test_bad_password_401(web_client):
    resp = web_client.post("/login", data={"username": "alice", "password": "nope"})
    assert resp.status_code == 401


def test_password_never_sent_to_api(web_client, monkeypatch):
    seen = {}
    def spy(url, json, headers, timeout):
        seen.update(json)
        raise web.httpx.ConnectError("down")
    monkeypatch.setattr(web.httpx, "post", spy)
    resp = web_client.post("/login", data={"username": "alice", "password": "correct horse"})
    assert "password" not in seen
    assert "Additional verification" in resp.text  # API down -> step-up, not allow
