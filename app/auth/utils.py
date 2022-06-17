import base64
import datetime
import hashlib
import math
import secrets
import typing

import sqlalchemy as sa
from core import config
from core.crud import CRUDModel
from jose import jwt

from . import models

settings = config.get_settings()


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
    async def authenticate(
        username: str,
        password: str,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ) -> dict | None:
        stmt = sa.select(models.users).where(
            models.users.c.username == username,
            models.users.c.is_active == True,
        )

        user_row = CRUDModel(conn).get_one(stmt)

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
            sa.select(models.permissions)
            .join_from(
                models.permissions,
                models.user_permissions,
            )
            .where(models.user_permissions.c.user_id == user_id)
        )

        return CRUDModel(conn).get_all(stmt)

    @staticmethod
    async def get_group_permissions(
        user_id: int,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ):
        # permissions belongs to group which belongs to user
        stmt = (
            sa.select(models.permissions)
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
            .where(models.user_groups.c.user_id == user_id)
        )

        return CRUDModel(conn).get_all(stmt)

    @staticmethod
    async def get_all_permissions(
        user_id: int,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ):
        # caching required
        # user permissions and group permissions
        pass

    @staticmethod
    async def has_perm(
        user_id: int,
        perm,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ):
        # member test
        pass

    @staticmethod
    async def has_module_perm(
        user_id: int,
        app_label: str,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ):
        # Return True if user_obj has any permissions in the given app_label.
        pass

    @staticmethod
    async def with_perm(
        perm,
        conn: sa.ext.asyncio.engine.AsyncConnection,
        is_active=True,
        include_superuser=True,
    ):
        """
        Return users that have permission "perm". By default, filter out
        inactive users and include superusers.
        """
        pass
