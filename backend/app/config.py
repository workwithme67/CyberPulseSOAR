"""
Application Configuration
==========================
Centralised settings loaded from environment variables / .env file.
Uses Pydantic Settings v2 for type-safe config with validation.

Usage
-----
  from app.config import settings

  print(settings.DATABASE_URL)
  print(settings.ABUSEIPDB_API_KEY)
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    All application settings.

    Values are read from environment variables first, then from a .env file.
    Fields with defaults are optional; fields without are required.
    """

    # ── Application ────────────────────────────────────────────────────────────
    APP_ENV: Literal["development", "staging", "production"] = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    DEBUG: bool = True
    PLAYBOOK_AUTO_TRIGGER: bool = True


    # ── Database ───────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite:///./soar.db"

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "soar.log"
    LOG_MAX_BYTES: int = 10 * 1024 * 1024   # 10 MB
    LOG_BACKUP_COUNT: int = 5

    # ── Security / JWT ────────────────────────────────────────────────────────
    SECRET_KEY: str = "change-me-in-production-use-256bit-random-string"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 8       # 8 hours default

    # ── Threat Intelligence API Keys ──────────────────────────────────────────
    # Leave empty → mock data will be used automatically
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    IPINFO_API_KEY: str = ""               # optional – free tier works without key

    # ── TI Request Settings ───────────────────────────────────────────────────
    TI_REQUEST_TIMEOUT: int = 10        # seconds
    TI_MAX_DAYS_CHECK: int = 90         # AbuseIPDB lookback window (days)

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS_ORIGINS: str = "*"             # comma-separated list for production

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def abuseipdb_enabled(self) -> bool:
        """True when a real AbuseIPDB API key is configured."""
        return bool(self.ABUSEIPDB_API_KEY and self.ABUSEIPDB_API_KEY != "your-abuseipdb-api-key")

    @property
    def virustotal_enabled(self) -> bool:
        """True when a real VirusTotal API key is configured."""
        return bool(self.VIRUSTOTAL_API_KEY and self.VIRUSTOTAL_API_KEY != "your-virustotal-api-key")

    @property
    def ipinfo_enabled(self) -> bool:
        """True when a real IPInfo API key is configured (optional)."""
        return bool(self.IPINFO_API_KEY and self.IPINFO_API_KEY != "your-ipinfo-api-key")

    @property
    def cors_origins_list(self) -> list[str]:
        """Return CORS_ORIGINS as a list."""
        if self.CORS_ORIGINS == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached Settings singleton.

    Using lru_cache means the .env file is read exactly once at startup.
    In tests, call get_settings.cache_clear() to reload.
    """
    return Settings()


# Module-level convenience alias
settings: Settings = get_settings()
