from datetime import datetime, timezone

from conf.config import get_settings
from conf.dependencies import engine_begin, engine_connect
from conf.exceptions import item_not_found_exception
from conf.responses import successful_response
from fastapi import APIRouter, Depends, Response, status
from fastapi.encoders import jsonable_encoder
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio.engine import AsyncConnection

from . import models, schemas
from .utils import Pbkdf2Sha256Hasher

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


@router.get(
    "/users",
    status_code=status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users(
    skip: int = 0,
    take: int = 100,
    is_active: bool = True,
    is_staff: bool = False,
    is_superuser: bool = False,
    conn: AsyncConnection = Depends(engine_connect),
):
    query = models.users.select()

    if is_active:
        query = query.where(models.users.c.is_active == is_active)
    if is_staff:
        query = query.where(models.users.c.is_staff == is_staff)
    if is_superuser:
        query = query.where(models.users.c.is_superuser == is_superuser)

    query = query.offset(skip).limit(take)

    cr: CursorResult = await conn.execute(query)

    return cr.fetchall()


@router.get(
    "/users/{user_id}",
    status_code=status.HTTP_200_OK,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def get_user(
    user_id: int,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.users.select().where(models.users.c.id == user_id)
    )

    if user_row := cr.first():
        return user_row

    raise item_not_found_exception("User")


@router.post(
    "/users/",
    status_code=status.HTTP_201_CREATED,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def create_user(
    user: schemas.UserCreate,
    conn: AsyncConnection = Depends(engine_begin),
):
    salt = Pbkdf2Sha256Hasher.salt()
    hash = Pbkdf2Sha256Hasher.hasher(user.password, salt)
    hashed_password = Pbkdf2Sha256Hasher.encode(hash, salt)

    user_dict = user.dict() | {
        "password": hashed_password,
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "date_joined": datetime.now(timezone.utc),
        "last_login": None,
    }

    await conn.execute(models.users.insert().values(**user_dict))

    return schemas.User(**user_dict)


@router.put(
    "/users/{user_id}",
    status_code=status.HTTP_200_OK,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def update_user(
    user_id: int,
    user: schemas.UserUpdate,
    conn: AsyncConnection = Depends(engine_begin),
):
    cr: CursorResult = await conn.execute(
        models.users.select().where(models.users.c.id == user_id)
    )

    # 1. Fetch saved row from database
    user_row = cr.first()

    if not user_row:
        raise item_not_found_exception("User")

    # 2. Create pydantic model instance from fetched row dict
    user_model = schemas.User(**user_row._mapping)

    # 3. Create user input dict from user input json (excludes fields unset)
    user_dict = user.dict(exclude_unset=True)

    # 4. Create NEW pydantic model from user_model + user_dict
    user_model_new = user_model.copy(update=user_dict)

    # 5. Update query
    await conn.execute(
        models.users.update()
        .where(models.users.c.id == user_id)
        .values(**user_model_new.dict())
    )

    # 6. Encode pydantic model into JSON
    return jsonable_encoder(user_model_new)


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_user(
    user_id: int,
    conn: AsyncConnection = Depends(engine_begin),
):
    cr: CursorResult = await conn.execute(
        models.users.select().where(models.users.c.id == user_id)
    )

    if user_row := cr.first():
        await conn.execute(models.users.delete().where(models.users.c.id == user_id))
        return None

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

    if content_type_row := cr.first():
        return content_type_row

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

    if content_type_row := cr.first():
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


@router.get(
    "/groups",
    status_code=status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups(
    skip: int = 0,
    take: int = 100,
    conn: AsyncConnection = Depends(engine_connect),
):
    query = models.groups.select().offset(skip).limit(take)

    cr: CursorResult = await conn.execute(query)

    return cr.fetchall()


@router.get(
    "/groups/{group_id}",
    status_code=status.HTTP_200_OK,
    response_model=schemas.Group,
)
async def get_group(
    group_id: int,
    conn: AsyncConnection = Depends(engine_connect),
):
    cr: CursorResult = await conn.execute(
        models.groups.select().where(models.groups.c.id == group_id)
    )

    if group_row := cr.first():
        return group_row

    raise item_not_found_exception("Group")


@router.post(
    "/groups/",
    status_code=status.HTTP_201_CREATED,
    response_model=schemas.Group,
)
async def create_group(
    group: schemas.GroupCreate,
    conn: AsyncConnection = Depends(engine_begin),
):
    await conn.execute(models.groups.insert().values(**group.dict()))

    return schemas.Group(**group.dict())


@router.put(
    "/groups/{group_id}",
    status_code=status.HTTP_200_OK,
    response_model=schemas.Group,
)
async def update_group(
    group_id: int,
    group: schemas.GroupUpdate,
    conn: AsyncConnection = Depends(engine_begin),
):
    cr: CursorResult = await conn.execute(
        models.groups.select().where(models.groups.c.id == group_id)
    )

    # 1. Fetch saved row from database
    group_row = cr.first()

    if not group_row:
        raise item_not_found_exception("Group")

    # 2. Create pydantic model instance from fetched row dict
    group_model = schemas.Group(**group_row._mapping)

    # 3. Create user input dict from user input json (excludes fields unset)
    group_dict = group.dict(exclude_unset=True)

    # 4. Create NEW pydantic model from user_model + user_dict
    group_model_new = group_model.copy(update=group_dict)

    # 5. Update query
    await conn.execute(
        models.groups.update()
        .where(models.groups.c.id == group_id)
        .values(**group_model_new.dict())
    )

    # 6. Encode pydantic model into JSON
    return jsonable_encoder(group_model_new)


@router.delete(
    "/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
async def delete_group(
    group_id: int,
    conn: AsyncConnection = Depends(engine_begin),
):
    cr: CursorResult = await conn.execute(
        models.groups.select().where(models.groups.c.id == group_id)
    )

    if group_row := cr.first():
        await conn.execute(models.groups.delete().where(models.groups.c.id == group_id))
        return None

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

    if permission_row := cr.first():
        return permission_row

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
