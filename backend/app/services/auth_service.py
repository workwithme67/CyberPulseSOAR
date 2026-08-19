"""
Authentication Service
======================
Handles user CRUD, login verification, and JWT issuance.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.models.user import User, UserRole
from app.models.schemas import UserCreate
from app.utils.security import hash_password, verify_password, create_access_token
from app.utils.helpers import get_logger

logger = get_logger(__name__)


# ── Create ────────────────────────────────────────────────────────────────────

def create_user(db: Session, payload: UserCreate) -> User:
    """Register a new user. Raises 409 if username/email already taken."""
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{payload.username}' is already taken.",
        )
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Email '{payload.email}' is already registered.",
        )

    user = User(
        username=payload.username,
        email=str(payload.email),
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("User created | username=%s role=%s", user.username, user.role)
    return user


# ── Read ──────────────────────────────────────────────────────────────────────

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def get_user_by_id(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id={user_id} not found.",
        )
    return user


def list_users(db: Session) -> list[User]:
    return db.query(User).order_by(User.created_at.desc()).all()


# ── Login ─────────────────────────────────────────────────────────────────────

def authenticate_user(db: Session, username: str, password: str) -> User:
    """Verify credentials. Raises 401 on failure."""
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled.",
        )
    logger.info("User authenticated | username=%s role=%s", user.username, user.role)
    return user


def issue_token(user: User) -> dict:
    """Return token response dict for a verified user."""
    expire_secs = settings.JWT_EXPIRE_MINUTES * 60
    token = create_access_token(
        data={"sub": user.username, "role": user.role, "user_id": user.id},
        expires_delta=timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
    )
    return {
        "access_token": token,
        "token_type":   "bearer",
        "expires_in":   expire_secs,
        "user":         user,
    }


# ── Seed default admin ─────────────────────────────────────────────────────────

def seed_default_admin(db: Session) -> None:
    """Ensure the default bootstrap admin exists with the documented password."""
    admin = get_user_by_username(db, "admin")
    if admin:
        admin.email = admin.email or "admin@soar.local"
        admin.full_name = admin.full_name or "SOAR Administrator"
        admin.hashed_password = hash_password("Admin@1234")
        admin.role = UserRole.Admin
        admin.is_active = True
        db.commit()
        db.refresh(admin)
        logger.info("Default admin user reset (admin / Admin@1234) – change immediately!")
        return

    from app.models.schemas import UserCreate as UC

    payload = UC(
        username="admin",
        email="admin@soar.local",
        full_name="SOAR Administrator",
        password="Admin@1234",
        role=UserRole.Admin,
    )
    create_user(db, payload)
    logger.info("Default admin user seeded (admin / Admin@1234) – change immediately!")
