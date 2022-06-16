import os
from functools import lru_cache

from pydantic import BaseSettings, Field, PostgresDsn


class Settings(BaseSettings):
    app_name: str = "fastapi-starter"

    uvicorn_reload: bool = False
    debug: bool = True
    host: str = "127.0.0.1"
    port: int = 8000

    secret_key: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"

    sqlalchemy_database_uri: PostgresDsn

    class Config:
        env_file_encoding = "utf-8"
        env_nested_delimiter = "__"
        env_file = (
            f'{os.getenv("ENV_STATE")}.env' if os.getenv("ENV_STATE") else "local.env"
        )


@lru_cache(maxsize=1)
def get_settings():
    return Settings()
