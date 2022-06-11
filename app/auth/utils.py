import abc
import base64
import hashlib
import math
import secrets


class Hasher(metaclass=abc.ABCMeta):
    @abc.abstractstaticmethod
    def salt():
        pass

    @abc.abstractstaticmethod
    def hasher():
        pass

    @abc.abstractstaticmethod
    def encode():
        pass

    @abc.abstractstaticmethod
    def decode():
        pass


class Pbkdf2Sha256Hasher(Hasher):
    RANDOM_STRING_CHARS = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )

    algorithm = "pbkdf2_sha256"
    iterations = 320000

    @staticmethod
    def salt():
        """Returns salt from random string (alphanumeric 22 chars).

        Returns:
            str: salt
        """
        # random string (alphanumeric 22 chars)
        char_count = math.ceil(
            128 / math.log2(len(Pbkdf2Sha256Hasher.RANDOM_STRING_CHARS))
        )  # 22
        return "".join(
            secrets.choice(Pbkdf2Sha256Hasher.RANDOM_STRING_CHARS)
            for i in range(char_count)
        )

    @staticmethod
    def hasher(plain, salt):
        """Returns encrypted password from plain password and salt.

        Args:
            plain (str): plain password text
            salt (str): salt

        Returns:
            str: encrypted password
        """
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
    def encode(hash, salt):
        """Returns one string concatenated with hash algorithm, iterations, hash and salt.
        The encoded text is seprated by $ character.

        Args:
            hash (bool): hashed password
            salt (str): salt

        Returns:
            _type_: encoded string to save as a field in database
        """
        return f"{Pbkdf2Sha256Hasher.algorithm}${Pbkdf2Sha256Hasher.iterations}${salt}${hash}"

    @staticmethod
    def decode(encoded):
        """Retruns decoded database value

        Args:
            encoded (str): encoded text

        Returns:
            dict: The result contains `algorithm`, `hash`, `iterations` and `salt`
        """
        algorithm, iterations, salt, hash = encoded.split("$", 3)
        return {
            "algorithm": algorithm,
            "hash": hash,
            "iterations": int(iterations),
            "salt": salt,
        }
