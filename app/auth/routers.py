from math import perm
from conf.config import get_settings
from conf.dependencies import engine_begin, engine_connect
from fastapi import APIRouter, Depends
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio.engine import AsyncConnection

from . import exceptions, models

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

    user = cr.first()

    if user:
        return user

    raise exceptions.user_not_found_exception()


@router.post("/users/")
async def create_user(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.put("/users/{user_id}")
async def update_user(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.delete("/users/{user_id}")
async def delete_user(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.put("/users/{user_id}/password")
async def change_password_of_user(conn: AsyncConnection = Depends(engine_begin)):
    return {}


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
        models.content_types.select().where(models.content_types.c.id == content_type_id)
    )

    content_type = cr.first()

    if content_type:
        return content_type

    raise exceptions.content_type_not_found_exception()

@router.post("/content-types/")
async def create_content_type(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.put("/content-types/{content_type_id}")
async def update_content_type(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.delete("/content-types/{content_type_id}")
async def delete_content_type(conn: AsyncConnection = Depends(engine_begin)):
    return {}


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

    group = cr.first()

    if group:
        return group

    raise exceptions.content_type_not_found_exception()


@router.post("/groups/")
async def create_group(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.put("/groups/{group_id}")
async def update_group(conn: AsyncConnection = Depends(engine_begin)):
    return {}


@router.delete("/groups/{group_id}")
async def delete_group(conn: AsyncConnection = Depends(engine_begin)):
    return {}


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
async def list_permissions(skip: int = 0,
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

    permission = cr.first()

    if permission:
        return permission

    raise exceptions.permission_not_found_exception()



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
async def list_superusers(skip: int = 0,
    take: int = 100,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.users.select().where(models.users.c.is_superuser==True) \
            .offset(skip)\
            .limit(take)
    )
    return cr.fetchall()



@router.post("/superusers")
async def create_superuser(conn: AsyncConnection = Depends(engine_connect)):
    return {}


@router.delete("/superusers/{user_id}")
async def delete_superuser(conn: AsyncConnection = Depends(engine_connect)):
    return {}
