from __future__ import annotations

import asyncio
import hmac
import json
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import ja4 as ja4_parser
from .config import Settings
from .models import FingerprintSummary, LoginCheckResponse, LoginEvent
from .rules import Detector, decide
from .store import WindowStore

log = logging.getLogger("abuse_detection_api")

PROXY_SECRET_HEADER = "x-huginn-proxy-secret"
SPOOFING_HEADER = "x-fingerprint-spoofing-detected"
# Headers only huginn-proxy may set. Trusted only alongside a valid proxy secret.
FINGERPRINT_HEADERS = (
    "x-tls-ja4",
    "x-tls-ja4-r",
    "x-tls-ja4-o",
    "x-tls-ja4-ro",
    "x-tls-ja4-s1",
    "x-tls-ja4-rs1",
    "x-http2-akamai",
    "x-tcp-p0f",
    SPOOFING_HEADER,
)


def _secure_equals(a: str, b: str) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    store = WindowStore(max_age_seconds=settings.retention_seconds)
    detector = Detector(settings, store)
    if not settings.service_token:
        log.warning("ABUSE_API_TOKEN is not set; every loginCheck call will be rejected")
    if not settings.proxy_shared_secret:
        log.warning("PROXY_SHARED_SECRET is not set; fingerprint headers will never be trusted")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async def sweeper() -> None:
            while True:
                await asyncio.sleep(60)
                store.sweep()

        task = asyncio.create_task(sweeper())
        yield
        task.cancel()

    app = FastAPI(title="Abuse Detection API", version="0.1.0", lifespan=lifespan)
    app.state.store = store
    bearer = HTTPBearer(auto_error=False)

    def require_service_token(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
        if creds is None or not _secure_equals(creds.credentials, settings.service_token):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid service token",
                                headers={"WWW-Authenticate": "Bearer"})

    def audit(version: str, event: LoginEvent, result: LoginCheckResponse) -> None:
        log.info(json.dumps({
            "msg": "login_check",
            "api_version": version,
            "username": event.username,
            "ip": str(event.ip),
            "outcome": event.outcome,
            "decision": result.decision.value,
            "reason": result.reason,
            "signals": [s.code for s in result.signals],
            "ja4": result.fingerprint.ja4 if result.fingerprint else None,
            "fingerprint_trusted": result.fingerprint.trusted if result.fingerprint else None,
        }))

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/loginCheck", response_model=LoginCheckResponse, dependencies=[Depends(require_service_token)])
    def login_check_v1(event: LoginEvent) -> LoginCheckResponse:
        signals = detector.evaluate_v1(event)
        decision, reason = decide(signals)
        detector.record(event)
        result = LoginCheckResponse(decision=decision, reason=reason, signals=signals, api_version="v1")
        audit("v1", event, result)
        return result

    @app.post("/v2/loginCheck", response_model=LoginCheckResponse, dependencies=[Depends(require_service_token)])
    def login_check_v2(event: LoginEvent, request: Request) -> LoginCheckResponse:
        headers = request.headers
        trusted = _secure_equals(headers.get(PROXY_SECRET_HEADER, ""), settings.proxy_shared_secret)
        present = [h for h in FINGERPRINT_HEADERS if h in headers]

        if trusted:
            ja4_raw = headers.get("x-tls-ja4")
            parsed = ja4_parser.parse(ja4_raw) if ja4_raw else None
            spoofed = [h.strip() for h in headers.get(SPOOFING_HEADER, "").split(",") if h.strip()]
            ignored: list[str] = []
        else:
            # Not from the proxy: fingerprint headers are ignored, never evaluated.
            ja4_raw, parsed, spoofed, ignored = None, None, [], present
            if ignored:
                log.warning(json.dumps({"msg": "untrusted_fingerprint_headers", "headers": ignored,
                                        "caller": request.client.host if request.client else None}))

        signals = detector.evaluate_v1(event)
        signals += detector.evaluate_fingerprint(
            event, trusted=trusted, ja4_raw=ja4_raw, ja4=parsed,
            spoofed_headers=spoofed, ignored_headers=ignored,
        )
        decision, reason = decide(signals)
        detector.record(event, ja4=parsed.raw if parsed else None)
        result = LoginCheckResponse(
            decision=decision, reason=reason, signals=signals, api_version="v2",
            fingerprint=FingerprintSummary(trusted=trusted, ja4=ja4_raw if trusted else None, ignored_headers=ignored),
        )
        audit("v2", event, result)
        return result

    return app
