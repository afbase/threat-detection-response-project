from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import BaseModel, Field


class Decision(StrEnum):
    ALLOW = "allow"
    STEP_UP = "step-up"
    DENY = "deny"

    @property
    def severity(self) -> int:
        return {"allow": 0, "step-up": 1, "deny": 2}[self.value]


class LoginEvent(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    ip: IPv4Address | IPv6Address
    user_agent: str = Field(default="", max_length=2048)
    timestamp: datetime
    outcome: Literal["success", "fail"]


class Signal(BaseModel):
    code: str
    decision: Decision
    detail: str


class FingerprintSummary(BaseModel):
    trusted: bool
    ja4: str | None = None
    ignored_headers: list[str] = []


class LoginCheckResponse(BaseModel):
    decision: Decision
    reason: str
    signals: list[Signal]
    api_version: Literal["v1", "v2"]
    fingerprint: FingerprintSummary | None = None
