"""
Database configuration and session management.

Reads DATABASE_URL from app.config (which reads from .env).
SQLite for development; swap DATABASE_URL for PostgreSQL in production.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings


def _resolve_database_url(database_url: str) -> str:
    """Resolve relative SQLite paths against the backend root directory."""
    if not database_url.startswith("sqlite:///") or database_url.startswith("sqlite:////"):
        return database_url

    raw_path = database_url.removeprefix("sqlite:///")
    db_path = Path(raw_path)
    if not db_path.is_absolute():
        db_path = (Path(__file__).resolve().parents[2] / db_path).resolve()

    return f"sqlite:///{db_path.as_posix()}"

# ── Engine ────────────────────────────────────────────────────────────────────
database_url = _resolve_database_url(settings.DATABASE_URL)

_connect_args = {"check_same_thread": False} if "sqlite" in database_url else {}

engine = create_engine(database_url, connect_args=_connect_args)

# ── Session factory ───────────────────────────────────────────────────────────
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ── Declarative base ──────────────────────────────────────────────────────────
Base = declarative_base()


# ── Request-scoped DB dependency ──────────────────────────────────────────────
def get_db():
    """FastAPI dependency that yields a per-request SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
