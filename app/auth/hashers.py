import base64
import hashlib
import math
import secrets
from functools import lru_cache


class Pbkdf2Sha256Hasher:
    RANDOM_STRING_CHARS = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )

    algorithm = "pbkdf2_sha256"
    iterations = 320000

    def salt(self) -> str:
        # random string (alphanumeric 22 chars)
        char_count = math.ceil(128 / math.log2(len(self.RANDOM_STRING_CHARS)))  # 22
        return "".join(
            secrets.choice(self.RANDOM_STRING_CHARS) for i in range(char_count)
        )

    def hasher(self, plain: str, salt: str) -> str:
        hash = hashlib.pbkdf2_hmac(
            hashlib.sha256().name,  # 'sha256',
            plain.encode(),  # bytecode
            salt.encode(),  # bytecode
            self.iterations,  # 320000
            None,
        )
        hash = base64.b64encode(hash).decode("ascii").strip()
        return hash

    def encode(self, hash: str, salt: str) -> str:
        return f"{self.algorithm}${self.iterations}${salt}${hash}"

    def decode(self, encoded: str) -> dict:
        algorithm, iterations, salt, hash = encoded.split("$", 3)
        return {
            "algorithm": algorithm,
            "hash": hash,
            "iterations": int(iterations),
            "salt": salt,
        }

    def get_hashed_password(self, plain: str) -> str:
        salt = self.salt()
        hash = self.hasher(plain, salt)
        hashed_password = self.encode(hash, salt)
        return hashed_password

    def verify_password(self, plain: str, encoded: str) -> bool:
        decoded = self.decode(encoded)
        hashed = self.hasher(plain, decoded["salt"])

        if hashed == decoded["hash"]:
            return True

        return False


@lru_cache(maxsize=1)
def get_hasher():
    return Pbkdf2Sha256Hasher()


hasher = get_hasher()