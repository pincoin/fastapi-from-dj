import fastapi
import sqlalchemy as sa
from core import exceptions
from core.config import settings
from core.crud import CRUDModel
from core.dependencies import engine_begin, engine_connect
from jose import JWTError, jwt

from . import models

oauth2_scheme = fastapi.security.OAuth2PasswordBearer(tokenUrl="/auth/token")


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
            raise exceptions.invalid_token_exception()

        return {"username": username, "id": user_id}
    except JWTError:
        raise exceptions.invalid_token_exception()


async def get_superuser(
    current_user: dict = fastapi.Depends(get_current_user),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> dict:
    stmt = sa.select(models.users).where(
        models.users.c.id == current_user["id"],
        models.users.c.is_active == True,
        models.users.c.is_superuser == True,
    )

    row = await CRUDModel(conn).get_one(stmt)

    return row._mapping if row else None
