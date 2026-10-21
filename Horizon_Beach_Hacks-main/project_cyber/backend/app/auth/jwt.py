"""
Contexta Backend - JWT Authentication

Access/refresh tokens, DB-backed current-user resolution (so disabled users and
revoked tokens are rejected immediately) and role-based access control.
"""

from datetime import datetime, timedelta, timezone
from typing import Callable, List, Optional
from uuid import UUID

import structlog
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from jwt import PyJWTError as JWTError
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User, UserRole

logger = structlog.get_logger()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.api_v1_prefix}/auth/login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl=f"{settings.api_v1_prefix}/auth/login", auto_error=False)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    user_id: str
    token_version: int = 0
    token_type: str = "access"


def _encode(user: User, token_type: str, expires: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
        "ver": user.token_version or 0,
        "type": token_type,
        "iat": now,
        "exp": now + expires,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_tokens_for_user(user: User) -> Token:
    access = _encode(user, "access", timedelta(minutes=settings.access_token_expire_minutes))
    refresh = _encode(user, "refresh", timedelta(days=settings.refresh_token_expire_days))
    return Token(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


def _unauthorized(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def decode_token(token: str, expected_type: str = "access") -> TokenData:
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub", "type"]},
        )
    except JWTError as exc:
        logger.warning("JWT verification failed", error=str(exc))
        raise _unauthorized()
    if payload.get("type") != expected_type or not payload.get("sub"):
        raise _unauthorized()
    return TokenData(
        user_id=payload["sub"],
        token_version=int(payload.get("ver", 0)),
        token_type=expected_type,
    )


async def load_user_for_token(db: AsyncSession, data: TokenData) -> User:
    try:
        uid = UUID(data.user_id)
    except ValueError:
        raise _unauthorized()
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if user is None or (user.token_version or 0) != data.token_version:
        raise _unauthorized("Session expired")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled")
    return user


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    return await load_user_for_token(db, decode_token(token, "access"))


# Backwards-compatible alias used throughout the routes.
get_current_active_user = get_current_user


def require_role(allowed_roles: List[UserRole]) -> Callable:
    """Dependency factory restricting an endpoint to the given roles."""

    async def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            logger.warning(
                "Access denied - insufficient role",
                user_id=str(user.id),
                role=user.role.value,
                required=[r.value for r in allowed_roles],
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return role_checker


# Convenience dependencies
require_admin = require_role([UserRole.ADMIN])
require_analyst = require_role([UserRole.ADMIN, UserRole.ANALYST])
