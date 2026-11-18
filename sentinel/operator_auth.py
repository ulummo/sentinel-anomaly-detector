"""Operator authentication primitives for Sentinel."""
from __future__ import annotations
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

ITERATIONS = 310_000
SESSION_HOURS = 12

def hash_password(password: str, *, salt: bytes | None = None) -> str:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return "pbkdf2_sha256" + "$" + str(ITERATIONS) + "$" + salt.hex() + "$" + digest.hex()

def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False

def new_session() -> tuple[str, str]:
    token = secrets.token_urlsafe(40)
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()

def session_expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat()