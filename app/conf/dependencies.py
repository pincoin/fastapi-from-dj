import typing

from conf import config

from .database import engine

settings = config.get_settings()


async def engine_begin() -> typing.Generator:
    async with engine.begin() as conn:
        yield conn
    await engine.dispose()


async def engine_connect() -> typing.Generator:
    async with engine.connect() as conn:
        yield conn
    await engine.dispose()
