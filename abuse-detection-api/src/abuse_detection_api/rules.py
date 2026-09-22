"""Decision criteria.

Every rule emits a ``Signal`` with its own decision. The final decision is the
most severe signal (deny > step-up > allow). Velocity rules look at *prior*
events only; the current event is recorded after it has been evaluated.

v1 criteria (username, IP, user agent, timestamp, outcome)
----------------------------------------------------------
deny     ip_failures_5m          >= 20 failed logins from this IP in 5 min
deny     user_failures_15m       >= 10 failed logins for this username in 15 min
deny     ip_distinct_users_10m   >= 10 distinct usernames failed from this IP in 10 min (stuffing)
deny     ip_distinct_users_60m   >= 30 distinct usernames failed from this IP in 60 min (spray)
step-up  the same four rules at their lower thresholds (5 / 3 / 5 / 15)
step-up  automation_user_agent   UA is empty or a known HTTP library / headless browser
step-up  clock_skew              event timestamp more than 5 min from server time
allow    no signal fired

v2 adds (TLS JA4 from huginn-proxy)
-----------------------------------
deny     fingerprint_spoofing    proxy reports the client tried to send its own fingerprint headers
deny     ja4_denylisted          JA4 is on the configured denylist
deny     legacy_tls              TLS version below 1.2
deny/su  ja4_failures_5m         >= 50 / 20 failed logins sharing this JA4 in 5 min
deny/su  ja4_distinct_users_10m  >= 30 / 15 distinct usernames failed with this JA4 in 10 min
deny/su  ip_distinct_ja4_10m     >= 5 / 3 distinct JA4s from this IP in 10 min (rotation/evasion)
deny/su  user_distinct_ja4_10m   >= 5 / 3 distinct JA4s for this username in 10 min
step-up  ua_fingerprint_mismatch UA claims a mainstream browser, but the TLS hello does not look like one
step-up  fingerprint_untrusted   no proxy-authenticated fingerprint (headers missing or not from the proxy)
step-up  fingerprint_malformed   proxy-supplied JA4 could not be parsed
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from .config import Settings
from .ja4 import JA4
from .models import Decision, LoginEvent, Signal
from .store import WindowStore

_AUTOMATION_UA = re.compile(
    r"curl|wget|python-requests|python-httpx|aiohttp|urllib|go-http-client|okhttp|"
    r"java/|libwww|httpie|scrapy|headlesschrome|phantomjs|puppeteer|playwright|selenium|bot\b",
    re.IGNORECASE,
)
_BROWSER_UA = re.compile(r"Mozilla/5\.0 .*(Chrome|Firefox|Safari|Edg)/", re.IGNORECASE)

MIN_BROWSER_CIPHERS = 10


def _tier(value: int, thresholds: tuple[int, int]) -> Decision | None:
    step_up, deny = thresholds
    if value >= deny:
        return Decision.DENY
    if value >= step_up:
        return Decision.STEP_UP
    return None


def _norm_user(username: str) -> str:
    return username.strip().lower()


class Detector:
    def __init__(self, settings: Settings, store: WindowStore) -> None:
        self.settings = settings
        self.t = settings.thresholds
        self.store = store

    # -- evaluation --------------------------------------------------------

    def _velocity(self, signals: list[Signal], code: str, value: int, thresholds: tuple[int, int], what: str) -> None:
        decision = _tier(value, thresholds)
        if decision:
            signals.append(Signal(code=code, decision=decision, detail=f"{value} {what}"))

    def evaluate_v1(self, event: LoginEvent, now: datetime | None = None) -> list[Signal]:
        now = now or datetime.now(UTC)
        ip, user = str(event.ip), _norm_user(event.username)
        s = self.store
        signals: list[Signal] = []

        self._velocity(signals, "ip_failures_5m", s.count(f"ip_fail:{ip}", 300),
                       self.t.ip_failures_5m, "failed logins from this IP in the last 5 min")
        self._velocity(signals, "user_failures_15m", s.count(f"user_fail:{user}", 900),
                       self.t.user_failures_15m, "failed logins for this username in the last 15 min")
        self._velocity(signals, "ip_distinct_users_10m", s.distinct(f"ip_fail_users:{ip}", 600),
                       self.t.ip_distinct_users_10m, "distinct usernames failed from this IP in 10 min")
        self._velocity(signals, "ip_distinct_users_60m", s.distinct(f"ip_fail_users:{ip}", 3600),
                       self.t.ip_distinct_users_60m, "distinct usernames failed from this IP in 60 min")

        ua = event.user_agent.strip()
        if not ua:
            signals.append(Signal(code="automation_user_agent", decision=Decision.STEP_UP, detail="empty user agent"))
        elif _AUTOMATION_UA.search(ua):
            signals.append(Signal(code="automation_user_agent", decision=Decision.STEP_UP,
                                  detail="user agent matches an automation client"))

        ts = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=UTC)
        skew = abs((now - ts).total_seconds())
        if skew > self.t.max_clock_skew_seconds:
            signals.append(Signal(code="clock_skew", decision=Decision.STEP_UP,
                                  detail=f"event timestamp is {int(skew)}s from server time"))
        return signals

    def evaluate_fingerprint(
        self,
        event: LoginEvent,
        *,
        trusted: bool,
        ja4_raw: str | None,
        ja4: JA4 | None,
        spoofed_headers: list[str],
        ignored_headers: list[str],
    ) -> list[Signal]:
        signals: list[Signal] = []
        if not trusted:
            detail = "request did not carry a valid proxy secret"
            if ignored_headers:
                detail += f"; ignored fingerprint headers: {', '.join(ignored_headers)}"
            signals.append(Signal(code="fingerprint_untrusted", decision=Decision.STEP_UP, detail=detail))
            return signals

        if spoofed_headers:
            signals.append(Signal(code="fingerprint_spoofing", decision=Decision.DENY,
                                  detail=f"client sent proxy-owned headers: {', '.join(spoofed_headers)}"))
        if ja4_raw is None:
            signals.append(Signal(code="fingerprint_untrusted", decision=Decision.STEP_UP,
                                  detail="proxy supplied no JA4 fingerprint"))
            return signals
        if ja4 is None:
            signals.append(Signal(code="fingerprint_malformed", decision=Decision.STEP_UP,
                                  detail="JA4 fingerprint could not be parsed"))
            return signals

        if ja4.raw in self.settings.ja4_denylist:
            signals.append(Signal(code="ja4_denylisted", decision=Decision.DENY, detail=f"JA4 {ja4.raw} is denylisted"))
        if not ja4.modern_tls:
            signals.append(Signal(code="legacy_tls", decision=Decision.DENY, detail=f"TLS version code {ja4.version}"))
        if _BROWSER_UA.search(event.user_agent) and (ja4.alpn != "h2" or ja4.cipher_count < MIN_BROWSER_CIPHERS):
            signals.append(Signal(
                code="ua_fingerprint_mismatch", decision=Decision.STEP_UP,
                detail=f"browser user agent but TLS offers ALPN={ja4.alpn}, {ja4.cipher_count} ciphers",
            ))

        ip, user, fp = str(event.ip), _norm_user(event.username), ja4.raw
        s = self.store
        self._velocity(signals, "ja4_failures_5m", s.count(f"ja4_fail:{fp}", 300),
                       self.t.ja4_failures_5m, "failed logins sharing this JA4 in 5 min")
        self._velocity(signals, "ja4_distinct_users_10m", s.distinct(f"ja4_fail_users:{fp}", 600),
                       self.t.ja4_distinct_users_10m, "distinct usernames failed with this JA4 in 10 min")
        # The current fingerprint counts toward rotation if it is new.
        ip_fps = len(s.values(f"ip_ja4:{ip}", 600) | {fp})
        user_fps = len(s.values(f"user_ja4:{user}", 600) | {fp})
        self._velocity(signals, "ip_distinct_ja4_10m", ip_fps,
                       self.t.ip_distinct_ja4_10m, "distinct JA4 fingerprints from this IP in 10 min")
        self._velocity(signals, "user_distinct_ja4_10m", user_fps,
                       self.t.user_distinct_ja4_10m, "distinct JA4 fingerprints for this username in 10 min")
        return signals

    # -- recording ---------------------------------------------------------

    def record(self, event: LoginEvent, ja4: str | None = None) -> None:
        ip, user = str(event.ip), _norm_user(event.username)
        s = self.store
        if event.outcome == "fail":
            s.record(f"ip_fail:{ip}")
            s.record(f"user_fail:{user}")
            s.record(f"ip_fail_users:{ip}", user)
            if ja4:
                s.record(f"ja4_fail:{ja4}")
                s.record(f"ja4_fail_users:{ja4}", user)
        if ja4:
            s.record(f"ip_ja4:{ip}", ja4)
            s.record(f"user_ja4:{user}", ja4)


def decide(signals: list[Signal]) -> tuple[Decision, str]:
    if not signals:
        return Decision.ALLOW, "no risk signals"
    worst = max(signals, key=lambda sig: sig.decision.severity)
    return worst.decision, f"{worst.code}: {worst.detail}"
