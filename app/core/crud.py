import sqlalchemy as sa
from sqlalchemy.ext.asyncio.engine import AsyncConnection


class CRUDModel:
    def __init__(self, conn: AsyncConnection):
        self.conn = conn

    async def findOne(self, tatement):
        pass

    async def findAll(self, statement):
        cr: sa.engine.CursorResult = await self.conn.execute(statement)
        return cr.fetchall()

    async def insert(statement):
        pass

    async def update(statement):
        pass

    async def delete(statement):
        pass
