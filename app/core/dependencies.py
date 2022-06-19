import typing

from .database import engine


async def engine_connect() -> typing.Generator:
    """
    “BEGIN (implicit)” starts transaction block by DBAPI (ie. PostgreSQL)
    even though SQLAlchemy did not actually send any command to the database.
    """
    async with engine.connect() as conn:
        yield conn
    await engine.dispose()
