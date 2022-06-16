import fastapi
from conf import config
from conf.exceptions import invalid_credentials_exception
from jose import JWTError, jwt

settings = config.get_settings()

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
            raise invalid_credentials_exception()

        return {"username": username, "id": user_id}
    except JWTError:
        raise invalid_credentials_exception()
