from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from fastapi import FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from . import session
from .users import UserStore

log = logging.getLogger("login_app")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

PROXY_SECRET_HEADER = "x-huginn-proxy-secret"
# Everything huginn-proxy injects that the Abuse Detection API may use. Forwarded verbatim;
# the API decides whether to trust them based on the proxy secret.
FORWARDED_PROXY_HEADERS = (
    PROXY_SECRET_HEADER,
    "x-tls-ja4",
    "x-tls-ja4-r",
    "x-tls-ja4-o",
    "x-tls-ja4-ro",
    "x-tls-ja4-s1",
    "x-tls-ja4-rs1",
    "x-http2-akamai",
    "x-tcp-p0f",
    "x-fingerprint-spoofing-detected",
)


@dataclass(frozen=True)
class Settings:
    abuse_api_url: str = "http://abuse-detection-api:8001"
    abuse_api_token: str = ""
    abuse_api_version: str = "v2"
    abuse_api_timeout: float = 2.0
    proxy_shared_secret: str = ""
    session_secret: str = ""
    secure_cookies: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            abuse_api_url=os.environ.get("ABUSE_API_URL", cls.abuse_api_url),
            abuse_api_token=os.environ.get("ABUSE_API_TOKEN", ""),
            abuse_api_version=os.environ.get("ABUSE_API_VERSION", "v2"),
            abuse_api_timeout=float(os.environ.get("ABUSE_API_TIMEOUT", "2.0")),
            proxy_shared_secret=os.environ.get("PROXY_SHARED_SECRET", ""),
            session_secret=os.environ.get("SESSION_SECRET") or secrets.token_urlsafe(32),
            secure_cookies=os.environ.get("SECURE_COOKIES", "true").lower() == "true",
        )


def client_ip(request: Request, settings: Settings) -> str:
    """X-Forwarded-For is only honoured on requests that provably came through the proxy."""
    peer = request.client.host if request.client else "0.0.0.0"
    secret = request.headers.get(PROXY_SECRET_HEADER, "")
    from_proxy = bool(settings.proxy_shared_secret) and hmac.compare_digest(
        secret.encode(), settings.proxy_shared_secret.encode()
    )
    xff = request.headers.get("x-forwarded-for")
    if from_proxy and xff:
        return xff.split(",")[0].strip()
    return peer


def create_app(settings: Settings | None = None, users: UserStore | None = None,
               transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    users = users or UserStore.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with httpx.AsyncClient(
            base_url=settings.abuse_api_url,
            timeout=settings.abuse_api_timeout,
            headers={"Authorization": f"Bearer {settings.abuse_api_token}"},
            transport=transport,
        ) as client:
            app.state.abuse_api = client
            yield

    app = FastAPI(title="Login Web App", version="0.1.0", lifespan=lifespan)

    async def check_abuse(request: Request, username: str, success: bool) -> tuple[str, str]:
        event = {
            "username": username,
            "ip": client_ip(request, settings),
            "user_agent": request.headers.get("user-agent", ""),
            "timestamp": datetime.now(UTC).isoformat(),
            "outcome": "success" if success else "fail",
        }
        forwarded = {h: v for h in FORWARDED_PROXY_HEADERS if (v := request.headers.get(h)) is not None}
        try:
            resp = await request.app.state.abuse_api.post(
                f"/{settings.abuse_api_version}/loginCheck", json=event, headers=forwarded
            )
            resp.raise_for_status()
            body = resp.json()
            return body["decision"], body["reason"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            # Fail safe: never grant a session without a decision.
            log.error(json.dumps({"msg": "abuse_api_unavailable", "error": repr(exc)}))
            return "step-up", "abuse detection unavailable"

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/login", status_code=status.HTTP_302_FOUND)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> Response:
        return templates.TemplateResponse(request, "login.html", {"error": None})

    @app.post("/login")
    async def login(request: Request, username: str = Form(max_length=256), password: str = Form(max_length=1024)) -> Response:
        success = users.verify(username, password)
        decision, reason = await check_abuse(request, username, success)
        log.info(json.dumps({"msg": "login", "username": username, "success": success,
                             "decision": decision, "reason": reason}))

        if decision == "deny":
            return templates.TemplateResponse(
                request, "login.html", {"error": "Login blocked. Please try again later."},
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if not success:
            return templates.TemplateResponse(
                request, "login.html", {"error": "Invalid username or password."},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if decision == "step-up":
            # MFA is out of scope; the step-up page stands in for the challenge.
            return templates.TemplateResponse(request, "step_up.html", {"username": username},
                                              status_code=status.HTTP_401_UNAUTHORIZED)

        response = RedirectResponse("/success", status_code=status.HTTP_302_FOUND)
        response.set_cookie(session.COOKIE_NAME, session.issue(settings.session_secret, username),
                            max_age=session.TTL_SECONDS, httponly=True, secure=settings.secure_cookies,
                            samesite="lax")
        return response

    @app.get("/success", response_class=HTMLResponse)
    def success(request: Request) -> Response:
        username = session.verify(settings.session_secret, request.cookies.get(session.COOKIE_NAME))
        if username is None:
            return RedirectResponse("/login", status_code=status.HTTP_302_FOUND)
        return templates.TemplateResponse(request, "success.html", {"username": username})

    @app.post("/logout")
    def logout() -> RedirectResponse:
        response = RedirectResponse("/login", status_code=status.HTTP_302_FOUND)
        response.delete_cookie(session.COOKIE_NAME)
        return response

    return app
