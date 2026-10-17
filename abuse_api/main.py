"""Abuse Detection API: internal, stateless risk decisions for login attempts.

State (sliding-window counters) lives in Redis, so this process holds none.
"""
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Literal, Optional

import redis
from fastapi import FastAPI, Request
from pydantic import BaseModel

# ---------- config ----------
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
PROXY_HMAC_KEY = os.getenv("PROXY_HMAC_KEY", "dev-only-change-me").encode()
SIG_MAX_AGE_S = 30
CLOCK_SKEW_S = 300

# Header names the proxy sets (adjust to match huginn-proxy config).
H_JA4, H_TS, H_SIG = "x-ja4", "x-ja4-ts", "x-ja4-sig"

AUTOMATION_UA = ("python-requests", "curl", "go-http-client", "wget", "httpx", "aiohttp")
JA4_DENYLIST: set[str] = set()  # load from FoxIO JA4+ DB later

log = logging.getLogger("abuse_api")
logging.basicConfig(level=logging.INFO, format="%(message)s")

app = FastAPI(title="Abuse Detection API")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


# ---------- models ----------
class LoginEvent(BaseModel):
    username: str
    ip: str
    user_agent: str
    timestamp: float  # unix seconds
    success: bool


class Verdict(BaseModel):
    verdict: Literal["allow", "step_up", "deny"]
    reason: str


# ---------- sliding-window helpers (Redis sorted sets) ----------
def _add(key: str, member: str, now: float, ttl: int) -> None:
    r.zadd(key, {member: now})
    r.zremrangebyscore(key, 0, now - ttl)
    r.expire(key, ttl)


def _count(key: str, now: float, window: int) -> int:
    return r.zcount(key, now - window, now)


def _distinct(key: str, now: float, window: int) -> int:
    # members are "value|unique" -> count distinct values in window
    members = r.zrangebyscore(key, now - window, now)
    return len({m.split("|", 1)[0] for m in members})


def record(ev: LoginEvent, ja4: Optional[str], now: float) -> None:
    uid = f"{now}-{os.urandom(4).hex()}"
    if not ev.success:
        _add(f"fail:ip:{ev.ip}", uid, now, 3600)
        _add(f"fail:user:{ev.username}", uid, now, 1800)
        _add(f"spray:ip:{ev.ip}", f"{ev.username}|{uid}", now, 3600)
        _add(f"dist:user:{ev.username}", f"{ev.ip}|{uid}", now, 1800)
        if ja4:
            _add(f"fail:ja4:{ja4}", f"{ev.username}|{uid}", now, 600)
    if ja4:
        _add(f"ja4s:ip:{ev.ip}", f"{ja4}|{uid}", now, 600)


# ---------- rules ----------
def v1_rules(ev: LoginEvent, now: float) -> Verdict:
    ip_fails_5m = _count(f"fail:ip:{ev.ip}", now, 300)
    ua = ev.user_agent.lower()

    if ip_fails_5m >= 20:
        return Verdict(verdict="deny", reason="ip_burst")
    if _distinct(f"spray:ip:{ev.ip}", now, 3600) >= 10:
        return Verdict(verdict="deny", reason="ip_spray")
    if any(tok in ua for tok in AUTOMATION_UA):
        return Verdict(verdict="deny", reason="automation_ua")
    if ip_fails_5m >= 5:
        return Verdict(verdict="step_up", reason="ip_elevated")
    if ev.success and _count(f"fail:user:{ev.username}", now, 900) >= 3:
        return Verdict(verdict="step_up", reason="success_after_failures")
    if _distinct(f"dist:user:{ev.username}", now, 1800) >= 5:
        return Verdict(verdict="step_up", reason="username_distributed")
    if abs(now - ev.timestamp) > CLOCK_SKEW_S:
        return Verdict(verdict="step_up", reason="clock_skew")
    return Verdict(verdict="allow", reason="no_risk_signal")


def ja4_matches_ua(ja4: str, ua: str) -> bool:
    # Placeholder: map known browser JA4 prefixes to UA families.
    # Real profiles come from the JA4+ database; until then, never flag.
    return True


def v2_rules(ev: LoginEvent, ja4: str, now: float) -> Verdict:
    rotating = _distinct(f"ja4s:ip:{ev.ip}", now, 600) >= 3
    ip_has_fails = _count(f"fail:ip:{ev.ip}", now, 600) > 0

    if ja4 in JA4_DENYLIST:
        return Verdict(verdict="deny", reason="ja4_denylist")
    if _distinct(f"fail:ja4:{ja4}", now, 600) >= 20:
        return Verdict(verdict="deny", reason="ja4_shared_failures")
    if rotating and ip_has_fails:
        return Verdict(verdict="deny", reason="ja4_rotation_with_failures")

    base = v1_rules(ev, now)
    if base.verdict != "allow":
        return base

    if not ja4_matches_ua(ja4, ev.user_agent):
        return Verdict(verdict="step_up", reason="ja4_ua_mismatch")
    if rotating:
        return Verdict(verdict="step_up", reason="ja4_rotation")
    if ev.success and not r.sismember(f"known_ja4:{ev.username}", ja4):
        if r.scard(f"known_ja4:{ev.username}") > 0:  # first-ever login is not "new"
            return Verdict(verdict="step_up", reason="ja4_new_for_user")
    return base


# ---------- trust: only accept proxy-signed fingerprints ----------
def trusted_ja4(req: Request, now: float) -> Optional[str]:
    ja4, ts, sig = req.headers.get(H_JA4), req.headers.get(H_TS), req.headers.get(H_SIG)
    if not (ja4 and ts and sig):
        return None
    try:
        if abs(now - float(ts)) > SIG_MAX_AGE_S:
            return None  # stale -> possible replay
    except ValueError:
        return None
    expected = hmac.new(PROXY_HMAC_KEY, f"{ja4}|{ts}".encode(), hashlib.sha256).hexdigest()
    return ja4 if hmac.compare_digest(expected, sig) else None


def _emit(endpoint: str, ev: LoginEvent, v: Verdict, ja4: Optional[str]) -> None:
    log.info(json.dumps({
        "service": "abuse_api", "endpoint": endpoint, "username": ev.username,
        "ip": ev.ip, "ja4": ja4, "verdict": v.verdict, "reason": v.reason,
    }))


# ---------- endpoints ----------
@app.post("/v1/loginCheck", response_model=Verdict)
def login_check_v1(ev: LoginEvent):
    now = time.time()
    record(ev, None, now)
    v = v1_rules(ev, now)
    _emit("v1", ev, v, None)
    return v


@app.post("/v2/loginCheck", response_model=Verdict)
def login_check_v2(ev: LoginEvent, request: Request):
    now = time.time()
    ja4 = trusted_ja4(request, now)
    record(ev, ja4, now)
    if ja4 is None:
        v = v1_rules(ev, now)
        v.reason += ",fingerprint_untrusted"
    else:
        v = v2_rules(ev, ja4, now)
        if ev.success and v.verdict == "allow":
            r.sadd(f"known_ja4:{ev.username}", ja4)
    _emit("v2", ev, v, ja4)
    return v


@app.get("/healthz")
def healthz():
    return {"ok": True}
