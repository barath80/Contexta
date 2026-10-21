"""
Contexta Backend - Configuration Module

All configuration is read from environment variables (or a local .env file).
In production the service refuses to start with default/placeholder secrets.
"""

from functools import lru_cache
from pathlib import Path
from typing import List, Optional
import json

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent

_INSECURE_SECRETS = {
    "",
    "change-me-in-production",
    "jwt-secret-change-me",
    "your-super-secret-key-change-in-production",
    "your-jwt-secret-key-change-in-production",
}


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Contexta"
    app_env: str = "development"  # development | test | production
    debug: bool = False
    secret_key: str = "change-me-in-production"
    api_v1_prefix: str = "/api/v1"

    # Database (SQLite for local development, PostgreSQL in production)
    database_url: str = f"sqlite+aiosqlite:///{(BACKEND_DIR / 'contexta.db').as_posix()}"

    # Redis (optional - used for rate limiting / caching when reachable)
    redis_url: Optional[str] = None

    # JWT
    jwt_secret_key: str = "jwt-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Bootstrap administrator (created on first start if no users exist)
    admin_email: Optional[str] = None
    admin_password: Optional[str] = None
    admin_full_name: str = "Administrator"
    allow_registration: bool = False  # self-service sign-up creates VIEWER accounts

    # Google Gemini
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_timeout_seconds: int = 60
    gemini_max_concurrency: int = 4

    # Threat feeds
    nvd_api_key: Optional[str] = None
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    feed_http_timeout_seconds: int = 60

    # Scheduler
    scheduler_enabled: bool = True
    cve_fetch_interval_hours: int = 6
    risk_calculation_interval_minutes: int = 15
    twin_sync_interval_minutes: int = 60

    # Initial data
    # Fetch KEV/NVD feeds in the background right after start-up.
    sync_feeds_on_startup: bool = True
    nvd_days_back: int = 14
    # CVEs enriched with NVD version data per sync (each costs one NVD request; raise it with an NVD_API_KEY)
    nvd_enrich_per_sync: int = 25
    nvd_min_cvss: float = 7.0

    # SIEM telemetry: events are pushed to POST /logs/ingest (X-API-Key or analyst JWT).
    ingest_api_key: Optional[str] = None

    # Risk model assumptions (Executive financial exposure)
    expected_downtime_days_critical: float = 3.0
    expected_downtime_days_default: float = 1.0
    critical_risk_sla_days: int = 7

    # Logging
    log_level: str = "INFO"
    log_format: str = "console"  # console | json

    # CORS
    cors_origins: str = (
        '["http://localhost:3000","http://127.0.0.1:3000",'
        '"http://localhost:3001","http://127.0.0.1:3001"]'
    )

    # Reverse proxy: only trust X-Forwarded-For when a proxy you control sets it
    trust_proxy_headers: bool = False
    trusted_proxy_hops: int = 1
    # Outbound webhooks may only target public addresses unless this is enabled
    allow_private_webhooks: bool = False

    # Rate limiting
    rate_limit_per_minute: int = 300
    login_rate_limit_per_minute: int = 10

    # Ledger signing key (PEM file path). Generated on first start if absent.
    ledger_key_path: str = str(BACKEND_DIR / "ledger_signing_key.pem")

    @field_validator("app_env")
    @classmethod
    def _normalise_env(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"development", "test", "production"}:
            raise ValueError("APP_ENV must be development, test or production")
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def sync_database_url(self) -> str:
        """Synchronous driver URL used by Alembic."""
        url = self.database_url
        if url.startswith("sqlite+aiosqlite"):
            return url.replace("sqlite+aiosqlite", "sqlite", 1)
        if "+asyncpg" in url:
            return url.replace("+asyncpg", "+psycopg2", 1)
        return url

    @property
    def cors_origins_list(self) -> List[str]:
        try:
            parsed = json.loads(self.cors_origins)
            if isinstance(parsed, list):
                return [str(o) for o in parsed]
        except json.JSONDecodeError:
            pass
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def gemini_configured(self) -> bool:
        key = (self.gemini_api_key or "").strip()
        return bool(key) and not key.startswith("your-")

    def validate_for_runtime(self) -> None:
        """Fail fast on unsafe production configuration."""
        if not self.is_production:
            return
        problems = []
        if self.secret_key in _INSECURE_SECRETS or len(self.secret_key) < 32:
            problems.append("SECRET_KEY must be set to a random string of 32+ characters")
        if self.jwt_secret_key in _INSECURE_SECRETS or len(self.jwt_secret_key) < 32:
            problems.append("JWT_SECRET_KEY must be set to a random string of 32+ characters")
        if self.debug:
            problems.append("DEBUG must be false in production")
        if "*" in self.cors_origins_list:
            problems.append("CORS_ORIGINS must list explicit origins, not *")
        if self.admin_password is not None and len(self.admin_password) < 12:
            problems.append("ADMIN_PASSWORD must be at least 12 characters in production")
        if problems:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(problems))


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
