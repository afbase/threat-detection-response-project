"""Minimal JA4 parser (https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).

A JA4 looks like ``t13d1516h2_8daaf6152771_02713d6af862``:

    t   13  d   15  16  h2 _ <sha256(ciphers)[:12]> _ <sha256(exts+sigalgs)[:12]>
    |   |   |   |   |   |
    |   |   |   |   |   +- ALPN: first+last char of first ALPN value ("00" = none)
    |   |   |   |   +----- number of extensions
    |   |   |   +--------- number of cipher suites
    |   |   +------------- d = SNI is a domain, i = no SNI / IP
    |   +----------------- TLS version (13, 12, 11, 10, s3, s2)
    +--------------------- t = TCP, q = QUIC, d = DTLS
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_JA4 = re.compile(
    r"^(?P<proto>[tqd])(?P<version>13|12|11|10|s3|s2|00)(?P<sni>[di])"
    r"(?P<ciphers>\d{2})(?P<exts>\d{2})(?P<alpn>[0-9a-zA-Z]{2})"
    r"_(?P<cipher_hash>[0-9a-f]{12})_(?P<ext_hash>[0-9a-f]{12})$"
)


@dataclass(frozen=True)
class JA4:
    raw: str
    proto: str
    version: str
    sni: str
    cipher_count: int
    extension_count: int
    alpn: str
    cipher_hash: str
    extension_hash: str

    @property
    def modern_tls(self) -> bool:
        return self.version in {"12", "13"}


def parse(value: str) -> JA4 | None:
    m = _JA4.match(value.strip())
    if not m:
        return None
    return JA4(
        raw=value.strip(),
        proto=m["proto"],
        version=m["version"],
        sni=m["sni"],
        cipher_count=int(m["ciphers"]),
        extension_count=int(m["exts"]),
        alpn=m["alpn"],
        cipher_hash=m["cipher_hash"],
        extension_hash=m["ext_hash"],
    )
