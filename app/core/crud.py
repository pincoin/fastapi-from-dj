import contextlib

import sqlalchemy as sa
from pydantic import BaseModel
from sqlalchemy.ext.asyncio.engine import AsyncConnection

from . import exceptions


class CRUDModel:
    def __init__(self, engine_connection: AsyncConnection):
        self.engine_connection = engine_connection

    @contextlib.contextmanager
    def transaction_begin(self):
        # Prevent transaction nesting
        # Will be removed in SQLAlchemy 2.0
        if not self.engine_connection.in_transaction():
            with self.engine_connection.begin():
                yield self.engine_connection
        else:
            """
            BEGIN (implicit) by PostgreSQL
            """
            yield self.engine_connection

    async def get_one(
        self,
        statement,
    ):
        cr: sa.engine.CursorResult = await self.engine_connection.execute(statement)
        return cr.first()

    async def get_one_or_404(
        self,
        statement,
        item: str = "Item",
    ):
        cr: sa.engine.CursorResult = await self.engine_connection.execute(statement)

        if row := cr.first():
            return row

        raise exceptions.item_not_found_exceptsion(item)

    async def get_all(
        self,
        statement,
    ):
        cr: sa.engine.CursorResult = await self.engine_connection.execute(statement)
        return cr.fetchall()

    async def insert(
        self,
        statement,
    ):
        with self.transaction_begin():
            cr: sa.engine.CursorResult = await self.engine_connection.execute(statement)
            await self.engine_connection.commit()

        return cr.inserted_primary_key[0]

    async def update_or_failure(
        self,
        statement,
        dict_in: dict,
        model_out: BaseModel,
    ):
        # 1. Fetch saved row from database
        stmt = sa.select(statement.table).where(statement.whereclause)
        row = await CRUDModel(self.engine_connection).get_one_or_404(
            stmt, model_out.Config().title
        )

        # 2. Create pydantic model instance from fetched row dict
        model = model_out(**row._mapping)

        # 3. Create NEW pydantic model from model + dict_in
        model_new = model.copy(update=dict_in)

        # 4. Execute upate query
        with self.transaction_begin():
            await self.engine_connection.execute(statement.values(**model_new.dict()))
            await self.engine_connection.commit()

        return model_new

    async def delete_one_or_404(
        self,
        statement,
        item: str = "Item",
    ):
        with self.transaction_begin():
            cr: sa.engine.CursorResult = await self.engine_connection.execute(statement)
            await self.engine_connection.commit()

        if cr.rowcount > 0:
            return None

        raise exceptions.item_not_found_exception(item)
