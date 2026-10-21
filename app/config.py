from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str = (
        "postgresql+psycopg://discovery_user:discovery_password@localhost:5433/discovery_metadata"
    )
    SAMPLE_LIMIT: int = 200
    CONNECT_TIMEOUT_SEC: int = 5
    STATEMENT_TIMEOUT_MS: int = 5000
    OPENBAO_ADDR: str = "http://127.0.0.1:8200"
    OPENBAO_MOUNT: str = "discovery"
    OPENBAO_TOKEN_FILE: str = "/run/secrets/openbao_token"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()