from .database import engine


async def engine_begin():
    async with engine.begin() as conn:
        yield conn
    await engine.dispose()


async def engine_connect():
    async with engine.connect() as conn:
        yield conn
    await engine.dispose()
