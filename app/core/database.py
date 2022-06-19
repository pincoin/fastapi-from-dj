from functools import lru_cache

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from .config import settings

kwargs = {"echo": settings.debug}

# SQLAlchemy engine instance (lazy initialization)
engine = create_async_engine(
    # dialect+driver://username:password@host:port/database
    settings.sqlalchemy_database_uri,
    **kwargs,
)


@lru_cache(maxsize=1)
def get_metadata() -> sa.sql.schema.MetaData:
    return sa.MetaData()


metadata: sa.sql.schema.MetaData = get_metadata()
