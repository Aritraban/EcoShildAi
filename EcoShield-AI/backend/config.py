"""Application configuration.

All settings can be overridden with environment variables (prefixed ``ECOSHIELD_``)
or a local ``.env`` file. Secrets are NEVER hard-coded here; production deployments
must inject them via the environment.
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ECOSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Core ---
    app_name: str = "EcoShield AI"
    environment: str = "development"  # development | staging | production
    debug: bool = True
    api_prefix: str = "/api"

    # --- Database ---
    # Defaults to a local SQLite file so the project runs out of the box.
    # Point this at PostgreSQL/MySQL in production, e.g.
    #   postgresql+psycopg2://user:pass@localhost:5432/ecoshield
    database_url: str = "sqlite:///./ecoshield.db"

    # --- Security / JWT ---
    # Override in production. A weak default is refused when environment=production.
    secret_key: str = "change-me-in-production-please-use-a-long-random-string"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # --- Cookies / CORS ---
    cookie_secure: bool = False  # set True behind HTTPS
    cookie_samesite: str = "lax"
    cors_origins: List[str] = Field(
        default_factory=lambda: ["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:5500"]
    )

    # --- Account protection ---
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    session_idle_timeout_minutes: int = 30

    # --- Rate limiting (requests per window) ---
    rate_limit_default: int = 120
    rate_limit_window_seconds: int = 60
    rate_limit_auth: int = 10  # stricter for login/register

    # --- AI ---
    anomaly_contamination: float = 0.1
    llm_enabled: bool = False
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    def validate_production(self) -> None:
        """Refuse to boot in production with insecure defaults."""
        if self.environment == "production":
            problems = []
            if "change-me" in self.secret_key or len(self.secret_key) < 32:
                problems.append("ECOSHIELD_SECRET_KEY must be a long random value")
            if not self.cookie_secure:
                problems.append("ECOSHIELD_COOKIE_SECURE must be true behind HTTPS")
            if self.debug:
                problems.append("ECOSHIELD_DEBUG must be false in production")
            if problems:
                raise RuntimeError("Insecure production configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_production()
    return settings


settings = get_settings()
