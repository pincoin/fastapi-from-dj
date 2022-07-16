import os
from functools import lru_cache

from pydantic import BaseSettings, Field, PostgresDsn


class Settings(BaseSettings):
    app_name: str = "fastapi-starter"

    uvicorn_reload: bool = False
    debug: bool = True
    host: str = "127.0.0.1"
    port: int = 8000

    jwt_access_secret_key: str = Field(min_length=32)
    jwt_access_expire_minutes: int = 30
    jwt_refresh_secret_key: str = Field(min_length=32)
    jwt_refresh_expire_days: int = 14
    jwt_algorithm: str = "HS256"
    password_hasher = "auth.hashers.Pbkdf2Sha256Hasher"
    authentication_backend = "auth.backends.AuthenticationBackend"

    sqlalchemy_database_uri: PostgresDsn

    class Config:
        env_file_encoding = "utf-8"
        env_nested_delimiter = "__"
        env_file = (
            f'{os.getenv("ENV_STATE")}.env' if os.getenv("ENV_STATE") else "local.env"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings: Settings = get_settings()
