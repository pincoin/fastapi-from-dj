import base64
import datetime
import hashlib
import math
import secrets
import typing

import fastapi
import sqlalchemy as sa
from core import config, exceptions
from core.crud import CRUDModel
from jose import JWTError, jwt

from . import models

settings = config.get_settings()

oauth2_scheme = fastapi.security.OAuth2PasswordBearer(tokenUrl="/auth/token")


class Pbkdf2Sha256Hasher:
    RANDOM_STRING_CHARS = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )

    algorithm = "pbkdf2_sha256"
    iterations = 320000

    @staticmethod
    def salt() -> str:
        # random string (alphanumeric 22 chars)
        char_count = math.ceil(
            128 / math.log2(len(Pbkdf2Sha256Hasher.RANDOM_STRING_CHARS))
        )  # 22
        return "".join(
            secrets.choice(Pbkdf2Sha256Hasher.RANDOM_STRING_CHARS)
            for i in range(char_count)
        )

    @staticmethod
    def hasher(plain: str, salt: str) -> str:
        hash = hashlib.pbkdf2_hmac(
            hashlib.sha256().name,  # 'sha256',
            plain.encode(),  # bytecode
            salt.encode(),  # bytecode
            Pbkdf2Sha256Hasher.iterations,  # 320000
            None,
        )
        hash = base64.b64encode(hash).decode("ascii").strip()
        return hash

    @staticmethod
    def encode(hash: str, salt: str) -> str:
        return f"{Pbkdf2Sha256Hasher.algorithm}${Pbkdf2Sha256Hasher.iterations}${salt}${hash}"

    @staticmethod
    def decode(encoded: str) -> dict:
        algorithm, iterations, salt, hash = encoded.split("$", 3)
        return {
            "algorithm": algorithm,
            "hash": hash,
            "iterations": int(iterations),
            "salt": salt,
        }

    @staticmethod
    def get_hashed_password(plain: str) -> str:
        salt = Pbkdf2Sha256Hasher.salt()
        hash = Pbkdf2Sha256Hasher.hasher(plain, salt)
        hashed_password = Pbkdf2Sha256Hasher.encode(hash, salt)
        return hashed_password

    @staticmethod
    def verify_password(plain: str, encoded: str) -> bool:
        decoded = Pbkdf2Sha256Hasher.decode(encoded)
        hashed = Pbkdf2Sha256Hasher.hasher(plain, decoded["salt"])

        if hashed == decoded["hash"]:
            return True

        return False


class AuthenticationBackend:
    @staticmethod
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

    @staticmethod
    async def authenticate(
        username: str,
        password: str,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ) -> dict | None:
        stmt = sa.select(models.users).where(
            models.users.c.username == username,
            models.users.c.is_active == True,
        )

        user_row = await CRUDModel(conn).get_one(stmt)

        if not user_row:
            return False

        user_dict = user_row._mapping

        if not Pbkdf2Sha256Hasher.verify_password(password, user_dict["password"]):
            return False

        return user_dict

    @staticmethod
    def create_access_token(
        username: str,
        user_id: int,
        expires_delta: datetime.timedelta | None,
    ) -> typing.Any:
        if expires_delta:
            expire = datetime.datetime.utcnow() + expires_delta
        else:
            expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)

        payload = {
            "sub": username,
            "id": user_id,
            "exp": expire,
        }

        return jwt.encode(
            payload,
            settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )

    @staticmethod
    async def get_user_permissions(
        user_id: int,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ):
        # permissions belongs to user
        stmt = (
            sa.select(
                models.permissions,
                models.content_types.c.app_label,
                models.content_types.c.model,
            )
            .join_from(
                models.content_types,
                models.permissions,
            )
            .join_from(
                models.permissions,
                models.user_permissions,
            )
            .join_from(
                models.user_permissions,
                models.user,
            )
            .where(
                models.users.c.user_id == user_id,
                models.users.c.is_active == True,
            )
        )

        return await CRUDModel(conn).get_all(stmt)

    @staticmethod
    async def get_group_permissions(
        user_id: int,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ):
        # permissions belongs to group which belongs to user
        stmt = (
            sa.select(
                models.permissions,
                models.content_types.c.app_label,
                models.content_types.c.model,
            )
            .join_from(
                models.content_types,
                models.permissions,
            )
            .join_from(
                models.permissions,
                models.group_permissions,
            )
            .join_from(
                models.group_permissions,
                models.groups,
            )
            .join_from(
                models.groups,
                models.user_groups,
            )
            .join_from(
                models.user_groups,
                models.users,
            )
            .where(
                models.users.c.user_id == user_id,
                models.users.c.is_active == True,
            )
        )

        return await CRUDModel(conn).get_all(stmt)

    @staticmethod
    async def get_all_permissions(
        user_id: int,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ):
        # 1. Caching required!
        # 2. Rules assumption required for tuning
        # - Rule 1: User-Permission many-to-many relations are disabled.
        # - Rule 2: Each user has to be a member of a group.
        # - Rule 3: User-Group relations is one-to-one.
        stmt1 = (
            sa.select(
                models.permissions,
                models.content_types.c.app_label,
                models.content_types.c.model,
            )
            .join_from(
                models.content_types,
                models.permissions,
            )
            .join_from(
                models.permissions,
                models.user_permissions,
            )
            .join_from(
                models.user_permissions,
                models.users,
            )
            .where(
                models.users.c.user_id == user_id,
                models.users.c.is_active == True,
            )
        )

        stmt2 = (
            sa.select(
                models.permissions,
                models.content_types.c.app_label,
                models.content_types.c.model,
            )
            .join_from(
                models.content_types,
                models.permissions,
            )
            .join_from(
                models.permissions,
                models.group_permissions,
            )
            .join_from(
                models.group_permissions,
                models.groups,
            )
            .join_from(
                models.groups,
                models.user_groups,
            )
            .join_from(
                models.user_groups,
                models.users,
            )
            .where(
                models.users.c.user_id == user_id,
                models.users.c.is_active == True,
            )
        )

        stmt = sa.union(stmt1, stmt2)

        return await CRUDModel(conn).get_all(stmt)

    @staticmethod
    async def has_perm(
        user_id: int,
        permission_id: int,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ):
        perms = await AuthenticationBackend.get_all_permissions(user_id, conn)
        return any(d["id"] == permission_id for d in [perm._mapping for perm in perms])

    @staticmethod
    async def has_module_perm(
        user_id: int,
        app_label: str,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ):
        perms = await AuthenticationBackend.get_all_permissions(user_id, conn)
        return any(
            d["app_label"] == app_label for d in [perm._mapping for perm in perms]
        )

    @staticmethod
    async def with_perm(
        permission_id: int,
        conn: sa.ext.asyncio.engine.AsyncConnection,
        is_active=True,
        include_superusers=True,
    ):
        stmt = (
            sa.select(models.users)
            .join_from(
                models.users,
                models.user_permissions,
            )
            .where(models.user_permissions.c.permission_id == permission_id)
        )

        if is_active:
            stmt = stmt.where(models.users.c.is_active == True)

        if not include_superusers:
            stmt = stmt.where(models.users.c.is_superuser == False)

        return await CRUDModel(conn).get_all(stmt)
