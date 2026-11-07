from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "IVM Platform"
    app_env: str = "development"
    database_url: str = "postgresql+psycopg://ivm:ivm_local_only@localhost:5432/ivm"
    secret_key: str = "change-this-demo-secret-before-deployment"
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-haiku-4-5-20251001"
    mfa_required: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
