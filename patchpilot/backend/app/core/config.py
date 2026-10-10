"""Application configuration via environment variables (Pydantic Settings v2)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All application settings. Loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── App ─────────────────────────────────────────────────────────────────
    APP_NAME: str = "PatchPilot"
    APP_VERSION: str = "0.1.0"
    APP_ENV: Literal["development", "production"] = "development"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # ─── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://patchpilot:patchpilot@localhost:5432/patchpilot"
    SYNC_DATABASE_URL: str = "postgresql+psycopg2://patchpilot:patchpilot@localhost:5432/patchpilot"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30

    # ─── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ─── Qdrant ───────────────────────────────────────────────────────────────
    QDRANT_URL: str = "http://localhost:6333"
    QDRANT_API_KEY: str = ""

    # ─── ML Service ───────────────────────────────────────────────────────────
    ML_SERVICE_URL: str = "http://localhost:8001"

    # ─── MLflow ───────────────────────────────────────────────────────────────
    MLFLOW_TRACKING_URI: str = "http://localhost:5000"
    MLFLOW_EXPERIMENT_NAME: str = "patchpilot"

    # ─── JWT / Auth ───────────────────────────────────────────────────────────
    JWT_SECRET: str = "CHANGE_ME"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TTL_MIN: int = 15
    REFRESH_TTL_DAYS: int = 30
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "strict"

    # ─── CORS ─────────────────────────────────────────────────────────────────
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    @property
    def CORS_ORIGINS_LIST(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    # ─── LLM ─────────────────────────────────────────────────────────────────
    LLM_PROVIDER: Literal["gemini", "ollama"] = "gemini"
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5-coder:7b"
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 4096
    LLM_TIMEOUT_SEC: float = 60.0
    LLM_MAX_RETRIES: int = 3
    DAILY_LLM_BUDGET_USD: float = 5.0

    # ─── Rate Limits ──────────────────────────────────────────────────────────
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_SCAN: str = "20/hour"
    RATE_LIMIT_EXPLAIN: str = "30/hour"
    RATE_LIMIT_PATCH: str = "20/hour"

    # ─── Upload Limits ────────────────────────────────────────────────────────
    MAX_UPLOAD_MB: int = 2
    MAX_PASTE_MB: int = 1
    MAX_ZIP_FILES: int = 200
    MAX_ZIP_EXPANDED_MB: int = 50

    # ─── Data Retention ───────────────────────────────────────────────────────
    RETENTION_DAYS: int = 30

    # ─── Model / KB ───────────────────────────────────────────────────────────
    MODEL_STAGE: str = "Production"
    KB_VERSION: str = "v1"

    # ─── Admin ────────────────────────────────────────────────────────────────
    ADMIN_EMAIL: str = "admin@patchpilot.dev"
    ADMIN_PASSWORD: str = "CHANGE_ME"
    DEMO_USER_EMAIL: str = "user@patchpilot.dev"
    DEMO_USER_PASSWORD: str = "CHANGE_ME"

    # ─── Worker ───────────────────────────────────────────────────────────────
    ARQ_WORKER_CONCURRENCY: int = 4
    SCAN_TIMEOUT_SEC: int = 120
    ANALYZER_TIMEOUT_SEC: int = 30

    # ─── Analyzers ────────────────────────────────────────────────────────────
    SEMGREP_RULES: str = "p/python-security,p/owasp-top-ten"

    @field_validator("JWT_SECRET")
    @classmethod
    def jwt_secret_not_default(cls, v: str) -> str:
        if v == "CHANGE_ME" and True:  # Allow in tests
            import warnings
            warnings.warn("JWT_SECRET is using the default insecure value. Set a real secret in production.", stacklevel=2)
        return v

    @model_validator(mode="after")
    def validate_llm_config(self) -> "Settings":
        if self.LLM_PROVIDER == "gemini" and not self.GEMINI_API_KEY:
            import warnings
            warnings.warn("LLM_PROVIDER=gemini but GEMINI_API_KEY is not set. LLM features will be unavailable.", stacklevel=2)
        return self


@lru_cache
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()


settings = get_settings()
