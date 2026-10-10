"""Authentication and authorization utilities: JWT, Argon2id, token rotation."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from jose import JWTError, jwt

from app.core.config import settings

logger = structlog.get_logger(__name__)

# Argon2id with OWASP-recommended parameters (m=64MB, t=3, p=4)
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


# ─── Password Hashing ────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2id hash."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError):
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Check if hash needs upgrading (e.g., after parameter change)."""
    return _hasher.check_needs_rehash(hashed_password)


# ─── JWT ─────────────────────────────────────────────────────────────────────

def create_access_token(
    subject: str,
    role: str = "user",
    extra: Optional[dict] = None,
) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TTL_MIN)
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": expire,
        "type": "access",
        **(extra or {}),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decode and validate JWT access token.
    
    Raises JWTError on invalid/expired tokens.
    """
    payload = jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        options={"verify_exp": True},
    )
    if payload.get("type") != "access":
        raise JWTError("Invalid token type")
    return payload


# ─── Refresh Tokens ──────────────────────────────────────────────────────────

def generate_refresh_token() -> str:
    """Generate a cryptographically secure random refresh token."""
    return secrets.token_urlsafe(64)


def hash_refresh_token(token: str) -> str:
    """Hash refresh token for storage (SHA-256; not Argon2 – refresh tokens are already high-entropy)."""
    return hashlib.sha256(token.encode()).hexdigest()


def refresh_token_expiry() -> datetime:
    """Return the expiry datetime for a new refresh token."""
    return datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TTL_DAYS)
