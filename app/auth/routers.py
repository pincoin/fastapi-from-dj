from conf.config import get_settings
from conf.dependencies import engine_begin, engine_connect
from conf.exceptions import item_not_found_exception
from conf.responses import successful_response
from fastapi import APIRouter, Depends
from sqlalchemy.engine import CursorResult, Row
from sqlalchemy.ext.asyncio.engine import AsyncConnection

from . import models

settings = get_settings()


router = APIRouter(
    prefix="/auth",
    tags=[
        "auth",
    ],
)


@router.post("/login")
async def login():
    return {}


@router.post("/logout")
async def logout():
    return {}


@router.get("/users")
async def list_users(
    skip: int = 0,
    take: int = 100,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.users.select().offset(skip).limit(take)
    )
    return cr.fetchall()


@router.get("/users/{user_id}")
async def get_user(
    user_id: int,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.users.select().where(models.users.c.id == user_id)
    )

    if user := cr.first():
        return user

    raise item_not_found_exception("User")


@router.post("/users/")
async def create_user(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.put("/users/{user_id}")
async def update_user(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    conn: AsyncConnection = Depends(engine_begin),
):
    cr: CursorResult = await conn.execute(
        models.users.select().where(models.users.c.id == user_id)
    )

    if user := cr.first():
        await conn.execute(models.users.delete().where(models.users.c.id == user_id))
        return successful_response(200)

    raise item_not_found_exception("User")


@router.get("/users/{user_id}/groups")
async def list_groups_of_user(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.get("/users/{user_id}/permissions")
async def list_permissions_of_user(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.get("/content-types")
async def list_content_types(
    skip: int = 0,
    take: int = 100,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.content_types.select().offset(skip).limit(take)
    )
    return cr.fetchall()


@router.get("/content_types/{content_type_id}")
async def get_content_type(
    content_type_id: int,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.content_types.select().where(
            models.content_types.c.id == content_type_id
        )
    )

    if content_type := cr.first():
        return content_type

    raise item_not_found_exception("Content Type")


@router.post("/content-types/")
async def create_content_type(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.put("/content-types/{content_type_id}")
async def update_content_type(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.delete("/content-types/{content_type_id}")
async def delete_content_type(
    content_type_id: int,
    conn: AsyncConnection = Depends(engine_begin),
):
    cr: CursorResult = await conn.execute(
        models.content_types.select().where(
            models.content_types.c.id == content_type_id
        )
    )

    if content_type := cr.first():
        await conn.execute(
            models.content_types.delete().where(
                models.content_types.c.id == content_type_id
            )
        )
        return successful_response(200)

    raise item_not_found_exception("Content Type")


@router.get("/content-types/{content_type_id}/permissions")
async def list_permissions_of_content_type(
    conn: AsyncConnection = Depends(engine_connect),
):
    return {}


@router.get("/groups")
async def list_groups(
    skip: int = 0,
    take: int = 100,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.groups.select().offset(skip).limit(take)
    )
    return cr.fetchall()


@router.get("/groups/{group_id}")
async def get_group(
    group_id: int,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.groups.select().where(models.groups.c.id == group_id)
    )

    if group := cr.first():
        return group

    raise item_not_found_exception("Group")


@router.post("/groups/")
async def create_group(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.put("/groups/{group_id}")
async def update_group(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.delete("/groups/{group_id}")
async def delete_group(
    group_id: int,
    conn: AsyncConnection = Depends(engine_begin),
):
    cr: CursorResult = await conn.execute(
        models.groups.select().where(models.groups.c.id == group_id)
    )

    if group := cr.first():
        await conn.execute(models.groups.delete().where(models.groups.c.id == group_id))
        return successful_response(200)

    raise item_not_found_exception("Group")


@router.get("/groups/{group_id}/users")
async def list_users_of_group(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.post("/groups/{group_id}/users/{user_id}")
async def create_user_of_group(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.delete("/groups/{group_id}/users/{user_id}")
async def delete_user_of_group(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.get("/permissions")
async def list_permissions(
    skip: int = 0,
    take: int = 100,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.permissions.select().offset(skip).limit(take)
    )
    return cr.fetchall()


@router.get("/permissions/{permission_id}")
async def get_permission(
    permission_id: int,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.permissions.select().where(models.permissions.c.id == permission_id)
    )

    if permission := cr.first():
        return permission

    raise item_not_found_exception("Permission")


@router.post("/permissions/")
async def create_permission(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.put("/permissions/{permission_id}")
async def update_permission(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.delete("/permissions/{permission_id}")
async def delete_permission(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.get("/permissions/{permission_id}/users")
async def list_users_of_permission(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.get("/permissions/{permission_id}/groups")
async def list_groups_of_permission(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.post("/permissions/{permission_id}/user/{user_id}")
async def create_permission_of_user(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.delete("/permissions/{permission_id}/user/{user_id}")
async def delete_permission_of_user(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.post("/permissions/{permission_id}/group/{group_id}")
async def create_permission_of_group(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.delete("/permissions/{permission_id}/group/{group_id}")
async def delete_permission_of_group(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.get("/permissions/{permission_id}/content-types")
async def list_content_types_of_permission(
    conn: AsyncConnection = Depends(engine_connect),
):
    return {}


@router.get("/superusers")
async def list_superusers(
    skip: int = 0,
    take: int = 100,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.users.select()
        .where(models.users.c.is_superuser == True)
        .offset(skip)
        .limit(take)
    )
    return cr.fetchall()
