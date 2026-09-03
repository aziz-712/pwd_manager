"""Settings. Every secret comes from the environment; none has a usable default."""

from __future__ import annotations

import secrets
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ZKVAULT_", env_file=".env", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./zkvault.db"

    # Signing key for access/refresh JWTs. MUST be set in production; a random
    # per-process value in dev means restarts invalidate tokens, which is fine.
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 15 * 60
    refresh_token_ttl_seconds: int = 30 * 24 * 3600
    mfa_challenge_ttl_seconds: int = 5 * 60

    # Independent key for the user-enumeration-resistant decoy KDF params.
    enumeration_secret: str = ""

    # Argon2id parameters for hashing the client-derived auth secret at rest.
    # The input is already a 32-byte high-entropy value, so this is belt and
    # braces rather than the primary defence -- but it costs little.
    server_argon2_time_cost: int = 3
    server_argon2_memory_kib: int = 64 * 1024
    server_argon2_parallelism: int = 2

    max_blob_bytes: int = 16 * 1024 * 1024
    rate_limit_auth_per_minute: int = 10
    rate_limit_sync_per_minute: int = 60
    rate_limit_default_per_minute: int = 240

    cors_origins: str = ""  # comma separated; empty = no browser client allowed
    require_https: bool = True  # redirect/refuse plaintext outside development

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod", "staging"}

    def resolved_jwt_secret(self) -> str:
        if self.jwt_secret:
            return self.jwt_secret
        if self.is_production:
            raise RuntimeError("ZKVAULT_JWT_SECRET must be set outside development")
        return _DEV_JWT_SECRET

    def resolved_enumeration_secret(self) -> str:
        if self.enumeration_secret:
            return self.enumeration_secret
        if self.is_production:
            raise RuntimeError("ZKVAULT_ENUMERATION_SECRET must be set outside development")
        return _DEV_ENUM_SECRET


_DEV_JWT_SECRET = secrets.token_urlsafe(48)
_DEV_ENUM_SECRET = secrets.token_urlsafe(48)


@lru_cache
def get_settings() -> Settings:
    return Settings()
