import datetime

import fastapi
import sqlalchemy as sa
from core import config, exceptions
from core.dependencies import engine_begin, engine_connect

from . import models, schemas
from .dependencies import get_current_user
from .utils import AuthenticationBackend, Pbkdf2Sha256Hasher

settings = config.get_settings()


router = fastapi.APIRouter(
    prefix="/auth",
    tags=[
        "auth",
    ],
)


@router.post(
    "/token",
    response_model=schemas.Token,
)
async def login_for_access_token(
    form_data: fastapi.security.OAuth2PasswordRequestForm = fastapi.Depends(),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    user_dict = await AuthenticationBackend.authenticate(
        form_data.username,
        form_data.password,
        conn,
    )

    if not user_dict:
        raise exceptions.invalid_credentials_exception()

    access_token_expires = datetime.timedelta(minutes=30)
    access_token = AuthenticationBackend.create_access_token(
        user_dict["username"],
        user_dict["id"],
        expires_delta=access_token_expires,
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@router.get(
    "/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users(
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    is_active: bool | None = True,
    is_staff: bool | None = False,
    is_superuser: bool | None = False,
    current_user: dict = fastapi.Depends(get_current_user),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    if current_user is None:
        raise exceptions.forbidden_exception()

    stmt = sa.select(models.users)

    if is_active:
        stmt = stmt.where(models.users.c.is_active == is_active)
    if is_staff:
        stmt = stmt.where(models.users.c.is_staff == is_staff)
    if is_superuser:
        stmt = stmt.where(models.users.c.is_superuser == is_superuser)

    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.get(
    "/users/{user_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def get_user(
    user_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = sa.select(models.users).where(models.users.c.id == user_id)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if user_row := cr.first():
        return user_row

    raise exceptions.item_not_found_exception("User")


@router.post(
    "/users/",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def create_user(
    user: schemas.UserCreate,
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    hashed_password = Pbkdf2Sha256Hasher.get_hashed_password(user.password)

    user_dict = user.dict() | {
        "password": hashed_password,
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "date_joined": datetime.datetime.utcnow(),
        "last_login": None,
    }

    stmt = models.users.insert().values(**user_dict)

    try:
        cr: sa.engine.CursorResult = await conn.execute(stmt)
        return schemas.User(
            **user_dict,
            id=cr.inserted_primary_key[0],
        )
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.put(
    "/users/{user_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def update_user(
    user: schemas.UserUpdate,
    user_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    # 1. Create user input dict from user input json (excludes fields unset)
    user_dict = user.dict(exclude_unset=True)

    if not user_dict:
        raise exceptions.bad_request_exception()

    # 2. Fetch saved row from database
    stmt = sa.select(models.users).where(models.users.c.id == user_id)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    user_row = cr.first()

    if not user_row:
        raise exceptions.item_not_found_exception("User")

    # 3. Create pydantic model instance from fetched row dict
    user_model = schemas.User(**user_row._mapping)

    # 4. Create NEW pydantic model from user_model + user_dict
    user_model_new = user_model.copy(update=user_dict)

    stmt = (
        models.users.update()
        .where(models.users.c.id == user_id)
        .values(**user_model_new.dict())
    )

    try:
        # 5. Execute update statement
        await conn.execute(stmt)

        # 6. Encode pydantic model into JSON
        return fastapi.encoders.jsonable_encoder(user_model_new)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/users/{user_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_user(
    user_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    stmt = sa.select(models.users).where(models.users.c.id == user_id)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if user_row := cr.first():
        stmt = models.users.delete().where(models.users.c.id == user_id)
        await conn.execute(stmt)
        return None

    raise exceptions.item_not_found_exception("User")


@router.get(
    "/users/{user_id}/groups",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups_of_user(
    user_id: int = fastapi.Query(gt=0),
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = (
        sa.select(models.groups)
        .join_from(
            models.groups,
            models.user_groups,
        )
        .where(models.user_groups.c.user_id == user_id)
    )
    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.get(
    "/users/{user_id}/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Permission],
)
async def list_permissions_of_user(
    user_id: int = fastapi.Query(gt=0),
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = (
        sa.select(models.permissions)
        .join_from(
            models.permissions,
            models.user_permissions,
        )
        .where(models.user_permissions.c.user_id == user_id)
    )
    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.get(
    "/content-types",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.ContentType],
)
async def list_content_types(
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    app_label: str | None = fastapi.Query(default=None, max_length=100),
    model: str | None = fastapi.Query(default=None, max_length=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = sa.select(models.content_types)

    if app_label:
        stmt = stmt.where(models.content_types.c.app_label == app_label)
    if model:
        stmt = stmt.where(models.content_types.c.app_label == model)

    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.get(
    "/content_types/{content_type_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.ContentType,
)
async def get_content_type(
    content_type_id: int = fastapi.Query(default=0, gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = sa.select(models.content_types).where(
        models.content_types.c.id == content_type_id
    )

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if content_type_row := cr.first():
        return content_type_row

    raise exceptions.item_not_found_exception("Content Type")


@router.post(
    "/content-types/",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.ContentType,
)
async def create_content_type(
    content_type: schemas.ContentTypeCreate,
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    stmt = models.content_types.insert().values(**content_type.dict())

    try:
        cr: sa.engine.CursorResult = await conn.execute(stmt)
        return schemas.ContentType(
            **content_type.dict(),
            id=cr.inserted_primary_key[0],
        )
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.put(
    "/content-types/{content_type_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.ContentType,
)
async def update_content_type(
    content_type: schemas.ContentTypeUpdate,
    content_type_id: int = fastapi.Query(default=0, gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    content_type_dict = content_type.dict(exclude_unset=True)

    if not content_type_dict:
        raise exceptions.bad_request_exception()

    stmt = sa.select(models.content_types).where(
        models.content_types.c.id == content_type_id
    )

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    content_type_row = cr.first()

    if not content_type_row:
        raise exceptions.item_not_found_exception("Content Type")

    content_type_model = schemas.ContentType(**content_type_row._mapping)

    content_type_model_new = content_type_model.copy(update=content_type_dict)

    stmt = (
        models.content_types.update()
        .where(models.content_types.c.id == content_type_id)
        .values(**content_type_model_new.dict())
    )

    try:
        await conn.execute(stmt)
        return fastapi.encoders.jsonable_encoder(content_type_model_new)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/content-types/{content_type_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_content_type(
    content_type_id: int = fastapi.Query(default=0, gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    stmt = sa.select(models.content_types).where(
        models.content_types.c.id == content_type_id
    )
    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if content_type_row := cr.first():
        stmt = models.content_types.delete().where(
            models.content_types.c.id == content_type_id
        )
        await conn.execute(stmt)
        return None

    raise exceptions.item_not_found_exception("Content Type")


@router.get(
    "/content-types/{content_type_id}/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Permission],
)
async def list_permissions_of_content_type(
    content_type_id: int = fastapi.Query(gt=0),
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = (
        sa.select(
            models.permissions,
            models.content_types,
        )
        .join_from(
            models.permissions,
            models.content_types,
        )
        .where(models.content_types.c.id == content_type_id)
    )
    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.post(
    "/content-types/{content_type_id}/permissions",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.Permission,
)
async def create_permission_of_content_type(
    permission: schemas.PermissionCreate,
    content_type_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    permission_dict = permission.dict()

    if permission_dict["content_type_id"] != content_type_id:
        raise exceptions.bad_request_exception()

    stmt = models.permissions.insert().values(**permission_dict)

    try:
        cr: sa.engine.CursorResult = await conn.execute(stmt)
        return schemas.Permission(
            **permission_dict,
            id=cr.inserted_primary_key[0],
        )
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.put(
    "/content-types/{content_type_id}/permissions/{permission_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.Permission,
)
async def update_permission_of_content_type(
    permission: schemas.PermissionUpdate,
    content_type_id: int = fastapi.Query(gt=0),
    permission_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    permission_dict = permission.dict(exclude_unset=True)

    if not permission_dict:
        raise exceptions.bad_request_exception()

    if permission_dict["content_type_id"] != content_type_id:
        raise exceptions.bad_request_exception()

    stmt = sa.select(models.permissions).where(models.permissions.c.id == permission_id)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    permission_row = cr.first()

    if not permission_row:
        raise exceptions.item_not_found_exception("Permission")

    permission_model = schemas.Permission(**permission_row._mapping)

    permission_model_new = permission_model.copy(update=permission_dict)

    stmt = (
        models.permissions.update()
        .where(models.permissions.c.id == permission_id)
        .values(**permission_model_new.dict())
    )

    try:
        await conn.execute(stmt)
        return fastapi.encoders.jsonable_encoder(permission_model_new)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/content-types/{content_type_id}/permissions/{permission_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_permission_of_content_type(
    content_type_id: int = fastapi.Query(gt=0),
    permission_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    stmt = sa.select(models.permissions).where(
        models.permissions.c.id == permission_id,
        models.permissions.c.content_type_id == content_type_id,
    )
    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if content_type_row := cr.first():
        stmt = models.permissions.delete().where(
            models.permissions.c.id == permission_id,
            models.permissions.c.content_type_id == content_type_id,
        )
        await conn.execute(stmt)
        return None

    raise exceptions.item_not_found_exception("Permission")


@router.get(
    "/groups",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups(
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = sa.select(models.groups).offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.get(
    "/groups/{group_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.Group,
)
async def get_group(
    group_id: int = fastapi.Query(default=0, gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = sa.select(models.groups).where(models.groups.c.id == group_id)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if group_row := cr.first():
        return group_row

    raise exceptions.item_not_found_exception("Group")


@router.post(
    "/groups/",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.Group,
)
async def create_group(
    group: schemas.GroupCreate,
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    stmt = models.groups.insert().values(**group.dict())
    try:
        cr: sa.engine.CursorResult = await conn.execute(stmt)
        return schemas.Group(
            **group.dict(),
            id=cr.inserted_primary_key[0],
        )
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.put(
    "/groups/{group_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.Group,
)
async def update_group(
    group: schemas.GroupUpdate,
    group_id: int = fastapi.Query(default=0, gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    group_dict = group.dict(exclude_unset=True)

    if not group_dict:
        raise exceptions.bad_request_exception()

    stmt = sa.select(models.groups).where(models.groups.c.id == group_id)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    group_row = cr.first()

    if not group_row:
        raise exceptions.item_not_found_exception("Group")

    group_model = schemas.Group(**group_row._mapping)

    group_model_new = group_model.copy(update=group_dict)

    stmt = (
        models.groups.update()
        .where(models.groups.c.id == group_id)
        .values(**group_model_new.dict())
    )

    try:
        await conn.execute(stmt)
        return fastapi.encoders.jsonable_encoder(group_model_new)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/groups/{group_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_group(
    group_id: int = fastapi.Query(default=0, gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    stmt = sa.select(models.groups).where(models.groups.c.id == group_id)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if group_row := cr.first():
        stmt = models.groups.delete().where(models.groups.c.id == group_id)
        await conn.execute(stmt)
        return None

    raise exceptions.item_not_found_exception("Group")


@router.get(
    "/groups/{group_id}/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users_of_group(
    group_id: int = fastapi.Query(gt=0),
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = (
        sa.select(models.users)
        .join_from(
            models.users,
            models.user_groups,
        )
        .where(models.groups.c.id == group_id)
    )
    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.get(
    "/users/{user_id}/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Permission],
)
async def list_permissions_of_group(
    group_id: int = fastapi.Query(gt=0),
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = (
        sa.select(models.permissions)
        .join_from(
            models.permissions,
            models.group_permissions,
        )
        .where(models.group_permissions.c.group_id == group_id)
    )
    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.post(
    "/groups/{group_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.UserGroup,
)
async def create_user_of_group(
    group_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    user_group_dict = {
        "user_id": user_id,
        "group_id": group_id,
    }

    stmt = models.user_groups.insert().values(**user_group_dict)

    try:
        cr: sa.engine.CursorResult = await conn.execute(stmt)
        return schemas.UserGroup(
            **user_group_dict,
            id=cr.inserted_primary_key[0],
        )
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/groups/{group_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_user_of_group(
    group_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    stmt = sa.select(models.user_groups).where(
        models.user_groups.c.user_id == user_id,
        models.user_groups.c.group_id == group_id,
    )
    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if content_type_row := cr.first():
        stmt = models.user_groups.delete().where(
            models.user_groups.c.user_id == user_id,
            models.user_groups.c.group_id == group_id,
        )
        await conn.execute(stmt)
        return None

    raise exceptions.item_not_found_exception("User Group")


@router.get(
    "/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Permission],
)
async def list_permissions(
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = sa.select(
        models.permissions,
        models.content_types.c.app_label,
        models.content_types.c.model,
    ).join_from(
        models.permissions,
        models.content_types,
    )
    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.get(
    "/permissions/{permission_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.Permission,
)
async def get_permission(
    permission_id: int = fastapi.Query(default=0, gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = (
        sa.select(
            models.permissions,
            models.content_types.c.app_label,
            models.content_types.c.model,
        )
        .join_from(
            models.permissions,
            models.content_types,
        )
        .where(models.permissions.c.id == permission_id)
    )

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if permission_row := cr.first():
        return permission_row

    raise exceptions.item_not_found_exception("Permission")


@router.get(
    "/permissions/{permission_id}/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users_of_permission(
    permission_id: int = fastapi.Query(gt=0),
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = (
        sa.select(models.users)
        .join_from(
            models.users,
            models.user_permissions,
        )
        .where(models.user_permissions.c.permission_id == permission_id)
    )
    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.get(
    "/permissions/{permission_id}/groups",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups_of_permission(
    permission_id: int = fastapi.Query(gt=0),
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = (
        sa.select(models.groups)
        .join_from(
            models.groups,
            models.group_permissions,
        )
        .where(models.permissions.c.permission_id == permission_id)
    )
    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()


@router.post(
    "/permissions/{permission_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.UserPermission,
)
async def create_permission_of_user(
    permission_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    user_permission_dict = {
        "permission_id": permission_id,
        "user_id": user_id,
    }

    stmt = models.user_permissions.insert().values(**user_permission_dict)

    try:
        cr: sa.engine.CursorResult = await conn.execute(stmt)
        return schemas.UserPermission(
            **user_permission_dict,
            id=cr.inserted_primary_key[0],
        )
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/permissions/{permission_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_permission_of_user(
    permission_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    stmt = sa.select(models.user_permissions).where(
        models.user_permissions.c.user_id == user_id,
        models.user_permissions.c.permission_id == permission_id,
    )
    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if user_permission_row := cr.first():
        stmt = models.user_permissions.delete().where(
            models.user_permissions.c.user_id == user_id,
            models.user_permissions.c.permission_id == permission_id,
        )
        await conn.execute(stmt)
        return None

    raise exceptions.item_not_found_exception("User Permission")


@router.post(
    "/permissions/{permission_id}/group/{group_id}",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.GroupPermission,
)
async def create_permission_of_group(
    permission_id: int = fastapi.Query(gt=0),
    group_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    group_permission_dict = {
        "permission_id": permission_id,
        "group_id": group_id,
    }

    stmt = models.group_permissions.insert().values(**group_permission_dict)

    try:
        cr: sa.engine.CursorResult = await conn.execute(stmt)
        return schemas.GroupPermission(
            **group_permission_dict,
            id=cr.inserted_primary_key[0],
        )
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/permissions/{permission_id}/groups/{group_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_permission_of_group(
    permission_id: int = fastapi.Query(gt=0),
    group_id: int = fastapi.Query(gt=0),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_begin),
):
    stmt = sa.select(models.group_permissions).where(
        models.group_permissions.c.group_id == group_id,
        models.group_permissions.c.permission_id == permission_id,
    )
    cr: sa.engine.CursorResult = await conn.execute(stmt)

    if group_permissions_row := cr.first():
        stmt = models.group_permissions.delete().where(
            models.group_permissions.c.group_id == group_id,
            models.group_permissions.c.permission_id == permission_id,
        )
        await conn.execute(stmt)
        return None

    raise exceptions.item_not_found_exception("User Permission")


@router.get(
    "/permissions/{permission_id}/content-types",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.ContentType],
)
async def list_content_types_of_permission(
    permission_id: int = fastapi.Query(gt=0),
    skip: int | None = fastapi.Query(default=0, ge=0),
    take: int | None = fastapi.Query(default=100, le=100),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
):
    stmt = (
        sa.select(models.content_types)
        .join_from(
            models.content_types,
            models.permissions,
        )
        .where(models.permissions.c.id == permission_id)
    )
    stmt = stmt.offset(skip).limit(take)

    cr: sa.engine.CursorResult = await conn.execute(stmt)

    return cr.fetchall()
