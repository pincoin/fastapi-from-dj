import os
import typing
from asyncio.log import logger

from core.utils import get_logger

from .database import engine

logger = get_logger()


async def engine_connect() -> typing.Generator:
    """
    “BEGIN (implicit)” starts transaction block by DBAPI (ie. PostgreSQL)
    even though SQLAlchemy did not actually send any command to the database.
    """
    async with engine.connect() as conn:
        logger.debug(f"engine.connect() - [{os.getpid()}]")
        yield conn

    logger.debug(f"engine implcit close()/dispose() - [{os.getpid()}]")
    # await engine.dispose()
