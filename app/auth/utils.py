import base64
import datetime
import hashlib
import math
import secrets
import typing

import sqlalchemy as sa
from conf import config
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


class Authentication:
    @staticmethod
    async def authenticate_user(
        username: str,
        password: str,
        conn: sa.ext.asyncio.engine.AsyncConnection,
    ) -> dict | None:
        stmt = sa.select(models.users).where(models.users.c.username == username)

        cr: sa.engine.CursorResult = await conn.execute(stmt)

        user_row = cr.first()

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
        expire = (
            datetime.datetime.utcnow() + expires_delta
            if expires_delta
            else datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        )

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
