"""
Contexta Backend - User Schemas
"""

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from app.models.user import UserRole


class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    full_name: Optional[str] = Field(default=None, max_length=255)


class RegisterRequest(UserBase):
    """Self-service sign-up (when enabled). Always creates a VIEWER."""

    password: str = Field(..., min_length=10, max_length=128)


class UserCreate(UserBase):
    """Administrator-created account."""

    password: str = Field(..., min_length=10, max_length=128)
    role: UserRole = UserRole.ANALYST


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, max_length=255)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=10, max_length=128)


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, max_length=255)
    preferences: Optional[Dict[str, Any]] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=10, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: UUID
    email: str  # not EmailStr: internal domains such as .local are valid for existing accounts
    username: str
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool
    is_verified: bool = False
    last_login_at: Optional[datetime] = None
    preferences: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = {"from_attributes": True}
