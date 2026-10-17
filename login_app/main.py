"""Login Web App: user-facing login flow. Never decides abuse itself."""
import hashlib
import hmac
import json
import logging
import os
import time

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

ABUSE_API_URL = os.getenv("ABUSE_API_URL", "http://abuse_api:8001")
FORWARD_HEADERS = ("x-ja4", "x-ja4-ts", "x-ja4-sig")  # passed through untouched

log = logging.getLogger("login_app")
logging.basicConfig(level=logging.INFO, format="%(message)s")

app = FastAPI(title="Login Web App")


# ---------- demo user store (PBKDF2 hashes, never plaintext) ----------
def _hash(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)


_SALT = b"demo-salt-change-me"
USERS = {"alice": _hash("correct horse", _SALT), "bob": _hash("battery staple", _SALT)}


def verify_password(username: str, password: str) -> bool:
    stored = USERS.get(username)
    candidate = _hash(password, _SALT)  # hash even if user is unknown (timing)
    return stored is not None and hmac.compare_digest(stored, candidate)


# ---------- pages ----------
LOGIN_PAGE = """<!doctype html><title>Sign in</title>
<h1>Sign in</h1>{msg}
<form method="post" action="/login">
  <label>Username <input name="username" required></label><br>
  <label>Password <input name="password" type="password" required></label><br>
  <button type="submit">Sign in</button>
</form>"""


@app.get("/login", response_class=HTMLResponse)
def get_login():
    return LOGIN_PAGE.format(msg="")


@app.get("/success", response_class=HTMLResponse)
def success():
    return "<!doctype html><title>Welcome</title><h1>You are signed in.</h1>"


@app.post("/login")
def post_login(request: Request, username: str = Form(...), password: str = Form(...)):
    ok = verify_password(username, password)

    # Proxy sets X-Forwarded-For; first hop is the real client.
    xff = request.headers.get("x-forwarded-for", "")
    ip = xff.split(",")[0].strip() or (request.client.host if request.client else "unknown")

    event = {  # note: password is NOT included
        "username": username,
        "ip": ip,
        "user_agent": request.headers.get("user-agent", ""),
        "timestamp": time.time(),
        "success": ok,
    }
    fwd = {h: request.headers[h] for h in FORWARD_HEADERS if h in request.headers}

    try:
        resp = httpx.post(f"{ABUSE_API_URL}/v2/loginCheck", json=event, headers=fwd, timeout=2.0)
        resp.raise_for_status()
        decision = resp.json()
    except httpx.HTTPError:
        # Fail closed-ish: API down -> require step-up rather than silently allow.
        decision = {"verdict": "step_up", "reason": "abuse_api_unavailable"}

    log.info(json.dumps({"service": "login_app", "username": username, "ip": ip,
                         "password_ok": ok, **decision}))

    verdict = decision["verdict"]
    if verdict == "deny" or not ok:
        # Same message for wrong password and deny: don't tell attackers which.
        return HTMLResponse(LOGIN_PAGE.format(msg="<p>Sign-in failed.</p>"), status_code=401)
    if verdict == "step_up":
        return HTMLResponse("<!doctype html><h1>Additional verification required.</h1>",
                            status_code=200)
    return RedirectResponse("/success", status_code=302)
