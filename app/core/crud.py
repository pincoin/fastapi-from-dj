import sqlalchemy as sa
from sqlalchemy.ext.asyncio.engine import AsyncConnection

from . import exceptions


class CRUDModel:
    def __init__(self, conn: AsyncConnection):
        self.conn = conn

    async def get_one(self, statement):
        cr: sa.engine.CursorResult = await self.conn.execute(statement)
        return cr.first()

    async def get_one_or_404(self, statement, item: str = "Item"):
        cr: sa.engine.CursorResult = await self.conn.execute(statement)

        if row := cr.first():
            return row

        raise exceptions.item_not_found_exception(item)

    async def get_all(self, statement):
        cr: sa.engine.CursorResult = await self.conn.execute(statement)
        return cr.fetchall()

    async def insert(self, statement):
        pass

    async def update(self, statement):
        pass

    async def delete(self, statement):
        await self.conn.execute(statement)
