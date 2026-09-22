"""Demo credential store. Passwords are held only as salted PBKDF2 hashes."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets

_ITERATIONS = 200_000


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)


class UserStore:
    def __init__(self, users: dict[str, str]) -> None:
        self._hashes = {name.lower(): hash_password(pw) for name, pw in users.items()}
        # Verified against for unknown usernames so timing does not reveal which accounts exist.
        self._dummy = hash_password(secrets.token_urlsafe(16))

    @classmethod
    def from_env(cls) -> UserStore:
        """DEMO_USERS='{"alice": "pw", ...}'. Falls back to two demo accounts."""
        raw = os.environ.get("DEMO_USERS")
        users = json.loads(raw) if raw else {"alice": "wonderland", "bob": "builder"}
        return cls(users)

    def verify(self, username: str, password: str) -> bool:
        known = username.strip().lower() in self._hashes
        salt, expected = self._hashes.get(username.strip().lower(), self._dummy)
        _, actual = hash_password(password, salt)
        return hmac.compare_digest(actual, expected) and known
