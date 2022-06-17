import sqlalchemy as sa
from sqlalchemy.ext.asyncio.engine import AsyncConnection

from . import exceptions


class CRUDModel:
    def __init__(self, conn: AsyncConnection):
        self.conn = conn

    async def get_one(
        self,
        statement,
    ):
        cr: sa.engine.CursorResult = await self.conn.execute(statement)
        return cr.first()

    async def get_one_or_404(
        self,
        statement,
        item: str = "Item",
    ):
        cr: sa.engine.CursorResult = await self.conn.execute(statement)

        if row := cr.first():
            return row

        raise exceptions.item_not_found_exceptsion(item)

    async def get_all(
        self,
        statement,
    ):
        cr: sa.engine.CursorResult = await self.conn.execute(statement)
        return cr.fetchall()

    async def insert(
        self,
        statement,
    ):
        cr: sa.engine.CursorResult = await self.conn.execute(statement)
        return cr.inserted_primary_key[0]

    async def update_or_failure(
        self,
        dict_in,
        model_class,
        table,
        where,
        item: str = "Item",
    ):
        # 1. Fetch saved row from database
        stmt = sa.select(table).where(where)
        row = await CRUDModel(self.conn).get_one_or_404(stmt, item)

        # 2. Create pydantic model instance from fetched row dict
        model = model_class(**row._mapping)

        # 3. Create NEW pydantic model from user_model + user_dict
        model_new = model.copy(update=dict_in)

        stmt = table.update().where(where).values(**model_new.dict())
        await self.conn.execute(stmt)

        return model_new

    async def delete_one_or_404(
        self,
        statement,
        item: str = "Item",
    ):
        cr: sa.engine.CursorResult = await self.conn.execute(statement)

        if cr.rowcount > 0:
            return None

        raise exceptions.item_not_found_exception(item)
