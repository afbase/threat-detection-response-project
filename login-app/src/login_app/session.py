"""Stateless HMAC-signed session cookie: ``<username>|<expiry>|<sig>``."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

COOKIE_NAME = "session"
TTL_SECONDS = 3600


def _sign(secret: str, payload: str) -> str:
    mac = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")


def issue(secret: str, username: str, now: float | None = None) -> str:
    payload = f"{base64.urlsafe_b64encode(username.encode()).decode()}|{int((now or time.time()) + TTL_SECONDS)}"
    return f"{payload}|{_sign(secret, payload)}"


def verify(secret: str, cookie: str | None, now: float | None = None) -> str | None:
    if not cookie or cookie.count("|") != 2:
        return None
    user_b64, expiry, sig = cookie.split("|")
    payload = f"{user_b64}|{expiry}"
    if not hmac.compare_digest(sig, _sign(secret, payload)):
        return None
    if not expiry.isdigit() or int(expiry) < (now or time.time()):
        return None
    return base64.urlsafe_b64decode(user_b64.encode()).decode()
