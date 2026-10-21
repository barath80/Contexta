"""
Contexta Backend - Authentication and user management routes
"""

from datetime import datetime
from typing import List
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import (
    Token, create_tokens_for_user, decode_token, get_current_user, load_user_for_token, require_admin,
)
from app.auth.password import hash_password, verify_password
from app.config import settings
from app.database import get_db
from app.ledger.chain import LedgerEventTypes
from app.models.user import User, UserRole
from app.schemas.user import (
    PasswordChange, ProfileUpdate, RefreshRequest, RegisterRequest, UserCreate, UserResponse, UserUpdate,
)
from app.services import ledger_service
from app.utils import ratelimit
from app.utils.net import client_ip

logger = structlog.get_logger()
router = APIRouter()
users_router = APIRouter()

# A real bcrypt hash used to equalise timing when the account does not exist.
_DUMMY_HASH = hash_password("timing-equaliser-not-a-real-password")


_client_ip = client_ip


@router.post("/login", response_model=Token)
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    ip = _client_ip(request)
    allowed, retry = await ratelimit.hit(f"login:{ip}", settings.login_rate_limit_per_minute)
    if not allowed:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts. Try again shortly.",
                            headers={"Retry-After": str(retry)})
    email = form.username.strip().lower()
    # Per-account throttle (15 min window) stops distributed guessing against one account
    acct_ok, acct_retry = await ratelimit.hit(f"login-acct:{email}", settings.login_rate_limit_per_minute * 3, 900)
    if not acct_ok:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts for this account. Try again later.",
                            headers={"Retry-After": str(acct_retry)})
    user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()
    password_ok = verify_password(form.password, user.hashed_password if user else _DUMMY_HASH)
    if not user or not password_ok:
        await ledger_service.safe_record(LedgerEventTypes.LOGIN_FAILED, actor=email, data={"ip": ip})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User account is disabled")
    user.last_login_at = datetime.utcnow()
    await db.commit()
    await ledger_service.safe_record(LedgerEventTypes.USER_LOGIN, actor=user.email, resource_type="user",
                                     resource_id=str(user.id), data={"ip": ip})
    return create_tokens_for_user(user)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    if not settings.allow_registration:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Self-service registration is disabled. Ask an administrator for an account.")
    email = data.email.lower()
    if (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    if (await db.execute(select(User).where(User.username == data.username))).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")
    user = User(email=email, username=data.username, full_name=data.full_name,
                hashed_password=hash_password(data.password), role=UserRole.VIEWER, preferences={})
    db.add(user)
    await db.flush()
    await ledger_service.safe_record(LedgerEventTypes.USER_CREATED, actor="self-registration",
                                     resource_type="user", resource_id=str(user.id), data={"email": email, "role": "viewer"})
    return user


@router.post("/refresh", response_model=Token)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    user = await load_user_for_token(db, decode_token(body.refresh_token, "refresh"))
    return create_tokens_for_user(user)


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    return user


@router.put("/me", response_model=UserResponse)
async def update_me(data: ProfileUpdate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if data.full_name is not None:
        user.full_name = data.full_name
    if data.preferences is not None:
        allowed = {"theme", "alert_min_severity", "alerts_seen_at", "date_format", "timezone"}
        user.preferences = {**(user.preferences or {}), **{k: v for k, v in data.preferences.items() if k in allowed}}
    await db.flush()
    return user


@router.post("/change-password")
async def change_password(data: PasswordChange, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    user.hashed_password = hash_password(data.new_password)
    user.token_version = (user.token_version or 0) + 1  # sign out every other session
    await db.flush()
    await ledger_service.safe_record(LedgerEventTypes.USER_UPDATED, actor=user.email, resource_type="user",
                                     resource_id=str(user.id), data={"change": "password"})
    return {"message": "Password changed. Please sign in again.", "tokens": create_tokens_for_user(user)}


@router.post("/logout")
async def logout(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    user.token_version = (user.token_version or 0) + 1  # revokes access and refresh tokens
    await db.flush()
    await ledger_service.safe_record(LedgerEventTypes.USER_LOGOUT, actor=user.email, resource_type="user", resource_id=str(user.id))
    return {"message": "Signed out"}


# ------------------------------------------------------------- administration
@users_router.get("", response_model=List[UserResponse])
async def list_users(_: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    return list((await db.execute(select(User).order_by(User.created_at))).scalars().all())


@users_router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(data: UserCreate, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    email = data.email.lower()
    if (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    if (await db.execute(select(User).where(User.username == data.username))).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")
    user = User(email=email, username=data.username, full_name=data.full_name, role=data.role, is_verified=True,
                hashed_password=hash_password(data.password), preferences={})
    db.add(user)
    await db.flush()
    await ledger_service.safe_record(LedgerEventTypes.USER_CREATED, actor=admin.email, resource_type="user",
                                     resource_id=str(user.id), data={"email": email, "role": data.role.value})
    return user


@users_router.patch("/{user_id}", response_model=UserResponse)
async def update_user(user_id: UUID, data: UserUpdate, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id and (data.is_active is False or (data.role and data.role != UserRole.ADMIN)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot disable or demote your own account")
    changes = {}
    if data.full_name is not None:
        user.full_name = data.full_name
    if data.role is not None and data.role != user.role:
        changes["role"] = data.role.value
        user.role = data.role
        user.token_version = (user.token_version or 0) + 1
    if data.is_active is not None and data.is_active != user.is_active:
        changes["is_active"] = data.is_active
        user.is_active = data.is_active
        user.token_version = (user.token_version or 0) + 1
    if data.password:
        user.hashed_password = hash_password(data.password)
        user.token_version = (user.token_version or 0) + 1
        changes["password"] = "reset"
    await db.flush()
    if changes:
        await ledger_service.safe_record(LedgerEventTypes.USER_UPDATED, actor=admin.email, resource_type="user",
                                         resource_id=str(user.id), data=changes)
    return user
