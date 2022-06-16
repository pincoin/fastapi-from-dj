from functools import lru_cache

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import create_async_engine

from .config import get_settings
from .utils import Singleton

settings = get_settings()

kwargs = {"echo": settings.debug}

# SQLAlchemy engine instance
# lazy initialization
engine = create_async_engine(
    # dialect+driver://username:password@host:port/database
    settings.sqlalchemy_database_uri,
    **kwargs,
)


@lru_cache(maxsize=1)
def get_metadata():
    return MetaData()


metadata = get_metadata()
