import typing

import fastapi
from jose import JWTError, jwt

from conf import config
from conf.exceptions import invalid_credentials_exception

from .database import engine

settings = config.get_settings()

oauth2_scheme = fastapi.security.OAuth2PasswordBearer(tokenUrl="token")


async def engine_begin() -> typing.Generator:
    async with engine.begin() as conn:
        yield conn
    await engine.dispose()


async def engine_connect() -> typing.Generator:
    async with engine.connect() as conn:
        yield conn
    await engine.dispose()


async def get_current_user(token: str = fastapi.Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )

        username: str = payload.get("sub")
        user_id: int = payload.get("id")

        if username is None or user_id is None:
            raise invalid_credentials_exception()

        return {"username": username, "id": user_id}
    except JWTError:
        raise invalid_credentials_exception()
