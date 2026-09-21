"""Password hashing and strength policy.

Argon2id is the primary algorithm (memory-hard, current OWASP recommendation).
bcrypt is supported as a fallback and for verifying legacy hashes. Plain-text
passwords are never stored, logged, or returned anywhere in the system.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError
import bcrypt

_argon2 = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def hash_password(password: str) -> str:
    """Return an Argon2id salted hash of the password."""
    return _argon2.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time-ish verification supporting Argon2id and legacy bcrypt."""
    if not stored_hash:
        return False
    if stored_hash.startswith("$argon2"):
        try:
            return _argon2.verify(stored_hash, password)
        except (VerifyMismatchError, InvalidHashError, Exception):
            return False
    if stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except ValueError:
            return False
    return False


def needs_rehash(stored_hash: str) -> bool:
    """True if the stored hash should be upgraded (e.g. legacy bcrypt -> argon2)."""
    if not stored_hash.startswith("$argon2"):
        return True
    try:
        return _argon2.check_needs_rehash(stored_hash)
    except Exception:
        return True


@dataclass
class StrengthResult:
    score: int  # 0..4
    ok: bool
    feedback: list[str]


def check_password_strength(password: str) -> StrengthResult:
    """Deterministic password policy used at registration and reset."""
    feedback: list[str] = []
    score = 0

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")
    if len(password) >= 12:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add an uppercase letter.")
    if re.search(r"[a-z]", password) and re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add a lowercase letter and a digit.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add a special character for extra strength.")

    common = {"password", "12345678", "qwerty", "letmein", "welcome1", "ecoshield"}
    if password.lower() in common:
        score = 0
        feedback.append("This password is too common.")

    score = min(score, 4)
    return StrengthResult(score=score, ok=score >= 3 and len(password) >= 8, feedback=feedback)
