from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Sentinel used to detect an unset secret; the validator below rejects it outside development.
DEFAULT_SECRET = "change-this-demo-secret-before-deployment"  # nosec B105


class Settings(BaseSettings):
    app_name: str = "IVM Platform"
    app_env: str = "development"
    database_url: str = "postgresql+psycopg://ivm:ivm_local_only@localhost:5432/ivm"
    secret_key: str = DEFAULT_SECRET
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-haiku-4-5-20251001"
    mfa_required: bool = False
    # Per-client requests per minute; raise only for automated test runs.
    login_rate_limit: int = 10
    ai_rate_limit: int = 20
    # Shared secret external ticketing systems use to sign webhook calls (HMAC-SHA256).
    integration_webhook_secret: str | None = None
    # Run SLA/exception jobs in this process. Disable on web replicas when scaling out and run
    # exactly one scheduler instance (see deploy/k8s/scheduler.yaml).
    scheduler_enabled: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def _require_strong_secret_outside_development(self) -> "Settings":
        if self.app_env.lower() not in {"development", "test"} and (
            self.secret_key == DEFAULT_SECRET or len(self.secret_key) < 32
        ):
            raise ValueError(
                "SECRET_KEY must be set to a unique value of at least 32 characters "
                f"when APP_ENV={self.app_env}"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
