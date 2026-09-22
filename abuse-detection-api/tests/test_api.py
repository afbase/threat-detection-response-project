from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from abuse_detection_api.app import create_app
from abuse_detection_api.config import Settings
from abuse_detection_api.store import WindowStore

TOKEN = "svc-token"
SECRET = "proxy-secret"
CHROME_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
CHROME_JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def client():
    return TestClient(create_app(Settings(service_token=TOKEN, proxy_shared_secret=SECRET)))


def event(username="alice", ip="203.0.113.7", outcome="fail", ua=CHROME_UA, ts=None):
    return {
        "username": username,
        "ip": ip,
        "user_agent": ua,
        "timestamp": (ts or datetime.now(UTC)).isoformat(),
        "outcome": outcome,
    }


def proxy_headers(ja4=CHROME_JA4, **extra):
    return {**AUTH, "x-huginn-proxy-secret": SECRET, "x-tls-ja4": ja4, **extra}


def test_requires_service_token(client):
    assert client.post("/v1/loginCheck", json=event()).status_code == 401
    bad = {"Authorization": "Bearer nope"}
    assert client.post("/v1/loginCheck", json=event(), headers=bad).status_code == 401


def test_v1_clean_login_allowed(client):
    r = client.post("/v1/loginCheck", json=event(outcome="success"), headers=AUTH).json()
    assert r["decision"] == "allow"
    assert r["reason"] == "no risk signals"


def test_v1_user_bruteforce_escalates(client):
    decisions = [
        client.post("/v1/loginCheck", json=event(ip=f"198.51.100.{i}"), headers=AUTH).json()["decision"]
        for i in range(12)
    ]
    assert decisions[:3] == ["allow"] * 3
    assert decisions[3] == "step-up"
    assert decisions[10] == "deny"


def test_v1_credential_stuffing_from_one_ip(client):
    for i in range(10):
        client.post("/v1/loginCheck", json=event(username=f"user{i}"), headers=AUTH)
    r = client.post("/v1/loginCheck", json=event(username="victim", outcome="success"), headers=AUTH).json()
    assert r["decision"] == "deny"
    assert r["reason"].startswith("ip_distinct_users_10m")


def test_v1_automation_ua_and_clock_skew(client):
    r = client.post("/v1/loginCheck", json=event(outcome="success", ua="python-requests/2.32"), headers=AUTH).json()
    assert r["decision"] == "step-up"
    old = datetime.now(UTC) - timedelta(hours=2)
    r = client.post("/v1/loginCheck", json=event(username="bob", outcome="success", ts=old), headers=AUTH).json()
    assert [s["code"] for s in r["signals"]] == ["clock_skew"]


def test_v2_trusted_fingerprint_allows(client):
    r = client.post("/v2/loginCheck", json=event(outcome="success"), headers=proxy_headers()).json()
    assert r["decision"] == "allow"
    assert r["fingerprint"] == {"trusted": True, "ja4": CHROME_JA4, "ignored_headers": []}


def test_v2_ignores_fingerprint_without_proxy_secret(client):
    headers = {**AUTH, "x-tls-ja4": "t10d0101h1_000000000000_000000000000"}  # would be legacy_tls deny
    r = client.post("/v2/loginCheck", json=event(outcome="success"), headers=headers).json()
    assert r["decision"] == "step-up"
    assert r["fingerprint"]["trusted"] is False
    assert r["fingerprint"]["ignored_headers"] == ["x-tls-ja4"]
    assert {s["code"] for s in r["signals"]} == {"fingerprint_untrusted"}


def test_v2_wrong_proxy_secret_is_untrusted(client):
    headers = proxy_headers(**{"x-huginn-proxy-secret": "guess"})
    r = client.post("/v2/loginCheck", json=event(outcome="success"), headers=headers).json()
    assert r["fingerprint"]["trusted"] is False


def test_v2_spoofing_attempt_denied(client):
    headers = proxy_headers(**{"x-fingerprint-spoofing-detected": "x-tls-ja4"})
    r = client.post("/v2/loginCheck", json=event(outcome="success"), headers=headers).json()
    assert r["decision"] == "deny"
    assert r["reason"].startswith("fingerprint_spoofing")


def test_v2_legacy_tls_and_ua_mismatch(client):
    r = client.post("/v2/loginCheck", json=event(outcome="success"),
                    headers=proxy_headers(ja4="t11d1516h2_8daaf6152771_02713d6af862")).json()
    assert r["decision"] == "deny"
    # Browser UA but no ALPN and few ciphers: looks like a script wearing a browser UA.
    r = client.post("/v2/loginCheck", json=event(username="bob", ip="192.0.2.9", outcome="success"),
                    headers=proxy_headers(ja4="t13d040800_aaaaaaaaaaaa_bbbbbbbbbbbb")).json()
    assert r["decision"] == "step-up"
    assert r["reason"].startswith("ua_fingerprint_mismatch")


def test_v2_fingerprint_rotation_from_one_ip(client):
    decisions = []
    for i in range(5):
        ja4 = f"t13d1516h2_{i:012x}_02713d6af862"
        r = client.post("/v2/loginCheck", json=event(username=f"u{i}", outcome="success"),
                        headers=proxy_headers(ja4=ja4)).json()
        decisions.append(r["decision"])
    assert decisions == ["allow", "allow", "step-up", "step-up", "deny"]


def test_v2_shared_ja4_stuffing_across_ips(client):
    for i in range(30):
        client.post("/v2/loginCheck", json=event(username=f"user{i}", ip=f"10.0.{i}.1"), headers=proxy_headers())
    r = client.post("/v2/loginCheck", json=event(username="new", ip="10.9.9.9", outcome="success"),
                    headers=proxy_headers()).json()
    assert r["decision"] == "deny"
    assert r["reason"].startswith("ja4_distinct_users_10m")


def test_store_never_keeps_more_than_an_hour():
    now = [0.0]
    store = WindowStore(clock=lambda: now[0])
    store.record("k", "a")
    now[0] = 3599
    assert store.count("k", 3600) == 1
    now[0] = 3601
    assert store.count("k", 3600) == 0
    assert len(store) == 0
    with pytest.raises(ValueError):
        WindowStore(max_age_seconds=3601)
