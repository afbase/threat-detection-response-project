"""Settings, read from the environment. Every threshold can be overridden."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _list(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    return frozenset(v.strip() for v in raw.split(",") if v.strip())


@dataclass(frozen=True)
class Thresholds:
    # (step-up at, deny at) counts of *prior* events inside the window.
    ip_failures_5m: tuple[int, int] = (5, 20)
    user_failures_15m: tuple[int, int] = (3, 10)
    ip_distinct_users_10m: tuple[int, int] = (5, 10)  # credential stuffing burst
    ip_distinct_users_60m: tuple[int, int] = (15, 30)  # low-and-slow spray
    ja4_failures_5m: tuple[int, int] = (20, 50)  # one fingerprint dominating failures
    ja4_distinct_users_10m: tuple[int, int] = (15, 30)
    ip_distinct_ja4_10m: tuple[int, int] = (3, 5)  # fingerprint rotation
    user_distinct_ja4_10m: tuple[int, int] = (3, 5)
    max_clock_skew_seconds: int = 300


@dataclass(frozen=True)
class Settings:
    # Bearer token the Login Web App must present on every call.
    service_token: str = ""
    # Secret huginn-proxy injects on every request it forwards. Fingerprint
    # headers are only trusted when this value is present and correct.
    proxy_shared_secret: str = ""
    # How long events are kept for velocity checks (hard-capped at 3600s).
    retention_seconds: int = 3600
    ja4_denylist: frozenset[str] = frozenset()
    thresholds: Thresholds = field(default_factory=Thresholds)

    @classmethod
    def from_env(cls) -> Settings:
        def pair(name: str, default: tuple[int, int]) -> tuple[int, int]:
            return (_int(f"{name}_STEP_UP", default[0]), _int(f"{name}_DENY", default[1]))

        d = Thresholds()
        return cls(
            service_token=os.environ.get("ABUSE_API_TOKEN", ""),
            proxy_shared_secret=os.environ.get("PROXY_SHARED_SECRET", ""),
            retention_seconds=min(_int("RETENTION_SECONDS", 3600), 3600),
            ja4_denylist=_list("JA4_DENYLIST"),
            thresholds=Thresholds(
                ip_failures_5m=pair("IP_FAILURES_5M", d.ip_failures_5m),
                user_failures_15m=pair("USER_FAILURES_15M", d.user_failures_15m),
                ip_distinct_users_10m=pair("IP_DISTINCT_USERS_10M", d.ip_distinct_users_10m),
                ip_distinct_users_60m=pair("IP_DISTINCT_USERS_60M", d.ip_distinct_users_60m),
                ja4_failures_5m=pair("JA4_FAILURES_5M", d.ja4_failures_5m),
                ja4_distinct_users_10m=pair("JA4_DISTINCT_USERS_10M", d.ja4_distinct_users_10m),
                ip_distinct_ja4_10m=pair("IP_DISTINCT_JA4_10M", d.ip_distinct_ja4_10m),
                user_distinct_ja4_10m=pair("USER_DISTINCT_JA4_10M", d.user_distinct_ja4_10m),
                max_clock_skew_seconds=_int("MAX_CLOCK_SKEW_SECONDS", d.max_clock_skew_seconds),
            ),
        )
