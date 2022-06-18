import fastapi
from core import exceptions
from core.config import settings
from jose import JWTError, jwt

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
