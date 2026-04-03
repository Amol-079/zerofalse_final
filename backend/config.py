"""Application configuration — validated on startup."""
import sys
import logging
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import field_validator

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    # Supabase
    SUPABASE_URL: str
    SUPABASE_SERVICE_KEY: str

    # Clerk
    CLERK_SECRET_KEY: str
    CLERK_WEBHOOK_SECRET: str

    # Redis
    REDIS_URL: str = "redis://redis:6379"

    # App
    CORS_ORIGINS: str = "http://localhost:3000"
    ENVIRONMENT: str = "development"
    MAX_REQUEST_BODY_BYTES: int = 1_048_576

    @field_validator("SUPABASE_URL")
    @classmethod
    def validate_supabase_url(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("SUPABASE_URL must start with https://")
        return v.rstrip("/")

    @field_validator("CLERK_SECRET_KEY")
    @classmethod
    def validate_clerk_key(cls, v: str) -> str:
        if not (v.startswith("sk_live_") or v.startswith("sk_test_")):
            raise ValueError("CLERK_SECRET_KEY must start with sk_live_ or sk_test_")
        return v

    @field_validator("CLERK_WEBHOOK_SECRET")
    @classmethod
    def validate_webhook_secret(cls, v: str) -> str:
        if not v.startswith("whsec_"):
            raise ValueError("CLERK_WEBHOOK_SECRET must start with whsec_")
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
