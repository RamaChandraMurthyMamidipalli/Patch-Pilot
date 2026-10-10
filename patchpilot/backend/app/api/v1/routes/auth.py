"""Auth endpoints: register, login, refresh, logout."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Annotated

import structlog
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps.auth import get_current_active_user
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    refresh_token_expiry,
    verify_password,
)
from app.models.models import AuditLog, RefreshToken, User
from app.schemas.schemas import (
    ErrorEnvelope,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)

logger = structlog.get_logger(__name__)
auth_router = APIRouter()


def _set_refresh_cookie(response: Response, token: str) -> None:
    """Set the refresh token as a secure httpOnly cookie."""
    response.set_cookie(
        key="refresh_token",
        value=token,
        max_age=settings.REFRESH_TTL_DAYS * 86400,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/api/v1/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Clear the refresh token cookie."""
    response.delete_cookie(key="refresh_token", path="/api/v1/auth")


@auth_router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    request_data: UserRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Register a new user. Email must be unique."""
    # Normalize email to lowercase
    email = request_data.email.lower()

    # Check for duplicate (use case-insensitive comparison; CITEXT would do this in PG)
    existing = await db.execute(
        select(User).where(User.email == email)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "EMAIL_TAKEN", "message": "Email already registered", "details": None}},
        )

    user = User(
        email=email,
        password_hash=hash_password(request_data.password),
        role="user",
    )
    db.add(user)
    await db.flush()

    # Audit log
    db.add(AuditLog(
        user_id=user.id,
        action="user.register",
        ip=request.client.host if request.client else None,
    ))
    await db.commit()

    logger.info("user_registered", user_id=user.id)
    return UserResponse.model_validate(user)


@auth_router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and receive JWT access token + refresh cookie",
)
async def login(
    request_data: UserLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate user. Returns access token + sets httpOnly refresh cookie."""
    email = request_data.email.lower()

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    # Always run verify_password to prevent timing attacks
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    valid = verify_password(
        request_data.password,
        user.password_hash if user else dummy_hash,
    )

    if not user or not valid or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "INVALID_CREDENTIALS", "message": "Invalid email or password", "details": None}},
        )

    # Generate tokens
    access_token = create_access_token(subject=user.id, role=user.role)
    refresh_raw = generate_refresh_token()
    family = secrets.token_hex(16)

    rt = RefreshToken(
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_raw),
        family=family,
        expires_at=refresh_token_expiry(),
        ip_address=request.client.host if request.client else None,
    )
    db.add(rt)

    user.last_login_at = datetime.now(timezone.utc)
    db.add(AuditLog(user_id=user.id, action="user.login", ip=request.client.host if request.client else None))
    await db.commit()

    _set_refresh_cookie(response, refresh_raw)
    logger.info("user_login", user_id=user.id)

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.JWT_ACCESS_TTL_MIN * 60,
    )


@auth_router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token and issue new access token",
)
async def refresh_tokens(
    request: Request,
    response: Response,
    refresh_token: Annotated[str | None, Cookie()] = None,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Use the httpOnly refresh cookie to get a new access + refresh token pair."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": {"code": "INVALID_REFRESH_TOKEN", "message": "Refresh token invalid or expired", "details": None}},
    )

    if not refresh_token:
        raise credentials_exception

    token_hash = hash_refresh_token(refresh_token)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
        )
    )
    rt = result.scalar_one_or_none()

    if not rt or rt.expires_at < datetime.now(timezone.utc):
        # Revoke entire family on reuse (token theft detection)
        if rt:
            await db.execute(
                __import__("sqlalchemy").update(RefreshToken)
                .where(RefreshToken.family == rt.family)
                .values(revoked=True)
            )
            await db.commit()
        raise credentials_exception

    # Fetch user
    user_result = await db.execute(select(User).where(User.id == rt.user_id, User.is_active == True))
    user = user_result.scalar_one_or_none()
    if not user:
        raise credentials_exception

    # Rotate: revoke old, create new
    rt.revoked = True
    new_refresh_raw = generate_refresh_token()
    new_rt = RefreshToken(
        user_id=user.id,
        token_hash=hash_refresh_token(new_refresh_raw),
        family=rt.family,  # Keep same family
        expires_at=refresh_token_expiry(),
        ip_address=request.client.host if request.client else None,
    )
    db.add(new_rt)
    new_access_token = create_access_token(subject=user.id, role=user.role)
    await db.commit()

    _set_refresh_cookie(response, new_refresh_raw)
    logger.info("token_refreshed", user_id=user.id)

    return TokenResponse(
        access_token=new_access_token,
        expires_in=settings.JWT_ACCESS_TTL_MIN * 60,
    )


@auth_router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke refresh token and clear cookie",
)
async def logout(
    response: Response,
    refresh_token: Annotated[str | None, Cookie()] = None,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke the current refresh token (server-side) and clear cookie."""
    if refresh_token:
        token_hash = hash_refresh_token(refresh_token)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        rt = result.scalar_one_or_none()
        if rt:
            rt.revoked = True
            await db.commit()

    _clear_refresh_cookie(response)
    logger.info("user_logout")
