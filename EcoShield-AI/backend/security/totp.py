"""Minimal TOTP (RFC 6238) implementation for optional 2FA/MFA.

No external dependency - uses HMAC-SHA1 with a 30-second step and 6 digits.
Secrets are stored base32-encoded; the QR/provisioning URI can be generated for
any standard authenticator app.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from typing import Optional
from urllib.parse import quote


def generate_secret(length: int = 20) -> str:
    raw = hashlib.sha256(struct.pack(">d", time.time() + length)).digest()[:length]
    return base64.b32encode(raw).decode("utf-8").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(secret + padding, casefold=True)


def _hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def current_code(secret: str, time_step: int = 30) -> str:
    counter = int(time.time()) // time_step
    return _hotp(_decode_secret(secret), counter)


def verify_code(secret: str, code: str, time_step: int = 30, window: int = 1) -> bool:
    """Verify a TOTP code allowing +/- ``window`` steps for clock drift."""
    if not secret or not code or not code.isdigit():
        return False
    counter = int(time.time()) // time_step
    for offset in range(-window, window + 1):
        if hmac.compare_digest(_hotp(_decode_secret(secret), counter + offset), code.zfill(6)):
            return True
    return False


def provisioning_uri(secret: str, account: str, issuer: str = "EcoShield AI") -> str:
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
