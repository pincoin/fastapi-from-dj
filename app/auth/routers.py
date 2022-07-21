import datetime
import typing

import fastapi
import sqlalchemy as sa
from core import exceptions
from core.config import settings
from core.dependencies import engine_connect
from core.persistence import Persistence
from core.utils import get_logger, list_params
from fastapi.param_functions import Form
from jose import JWTError, jwt

from . import hashers, models, schemas
from .backends import authentication

logger = get_logger()

router = fastapi.APIRouter(
    prefix="/auth",
    tags=[
        "auth",
    ],
)


class OAuth2RequestForm:
    def __init__(
        self,
        grant_type: str = Form(default=None, regex="password|refresh_token"),
        username: str | None = Form(default=None),
        password: str | None = Form(default=None),
        refresh_token: str | None = Form(default=None),
        scope: str = Form(default=""),
        client_id: str | None = Form(default=None),
        client_secret: str | None = Form(default=None),
    ):
        self.grant_type = grant_type
        self.username = username
        self.password = password
        self.refresh_token = refresh_token
        self.scopes = scope.split()
        self.client_id = client_id
        self.client_secret = client_secret


@router.post(
    "/token",
    # response model is not specified to support both grant type `password` and `refresh_token`.
)
async def get_access_token(
    response: fastapi.Response,
    form_data: OAuth2RequestForm = fastapi.Depends(),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> dict:
    if form_data.grant_type == "password" and form_data.username and form_data.password:
        user_dict = await authentication.authenticate(
            form_data.username,
            form_data.password,
            conn,
        )

        if not user_dict:
            raise exceptions.invalid_credentials_exception()

        access_token_expires = datetime.timedelta(
            minutes=settings.jwt_expiration_delta,
        )
        access_token = authentication.create_access_token(
            user_dict["username"],
            user_dict["id"],
            expires_delta=access_token_expires,
        )

        refresh_token_expires = datetime.timedelta(
            minutes=settings.jwt_refresh_expiration_delta,
        )
        refresh_token = authentication.create_refresh_token(
            user_dict["id"],
            expires_delta=refresh_token_expires,
        )

        response.headers["cache-control"] = "no-store"

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    elif form_data.grant_type == "refresh_token" and form_data.refresh_token:
        try:
            payload = jwt.decode(
                form_data.refresh_token,
                settings.jwt_refresh_secret_key,
                algorithms=[settings.jwt_algorithm],
            )

            if datetime.datetime.fromtimestamp(
                payload["exp"], tz=datetime.timezone.utc
            ) < datetime.datetime.now(tz=datetime.timezone.utc):
                raise exceptions.invalid_token_exception()

            user_id: int = payload.get("id")

            stmt = (
                sa.select(
                    models.tokens,
                    models.users.c.username,
                )
                .join_from(
                    models.tokens,
                    models.users,
                )
                .where(
                    models.tokens.c.user_id == user_id,
                    models.users.c.is_active == True,
                )
            )

            if (token_row := await Persistence(conn).get_one_or_none(stmt)) is None:
                raise exceptions.invalid_token_exception()

            token_dict = token_row._mapping

            if token_dict["username"] is None or user_id is None:
                raise exceptions.invalid_token_exception()

            access_token_expires = datetime.timedelta(
                minutes=settings.jwt_expiration_delta,
            )
            access_token = authentication.create_access_token(
                token_dict["username"],
                user_id,
                expires_delta=access_token_expires,
            )

            response.headers["cache-control"] = "no-store"

            return {
                "access_token": access_token,
                "token_type": "bearer",
            }
        except JWTError:
            raise exceptions.invalid_token_exception()

    raise exceptions.bad_request_exception()


@router.post(
    "/refresh",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.RefreshToken,
)
async def get_refresh_token(
    response: fastapi.Response,
    user: dict = fastapi.Depends(authentication.get_current_user),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> dict:
    logger.debug("get refresh token")
    if user is None:
        raise exceptions.forbidden_exception()

    logger.debug(user)
    refresh_token_expires = datetime.timedelta(
        minutes=settings.jwt_refresh_expiration_delta,
    )
    refresh_token = authentication.create_refresh_token(
        user["id"],
        expires_delta=refresh_token_expires,
    )

    logger.debug(refresh_token)

    token_dict = {
        "user_id": user["id"],
        "token": refresh_token,
        "expiration_time_delta": refresh_token_expires,
        "created": datetime.datetime.now(),
    }

    logger.debug(token_dict)

    stmt = models.tokens.insert().values(**token_dict)
    try:
        await Persistence(conn).insert(stmt)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()

    response.headers["cache-control"] = "no-store"

    return {
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.get(
    "/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users(
    is_active: bool | None = True,
    is_staff: bool | None = False,
    is_superuser: bool | None = False,
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = sa.select(models.users)

    if is_active:
        stmt = stmt.where(models.users.c.is_active == is_active)
    if is_staff:
        stmt = stmt.where(models.users.c.is_staff == is_staff)
    if is_superuser:
        stmt = stmt.where(models.users.c.is_superuser == is_superuser)

    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)


@router.get(
    "/users/{user_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def get_user(
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = sa.select(models.users).where(models.users.c.id == user_id)
    return await Persistence(conn).get_one_or_404(stmt, schemas.User.Config().title)


@router.post(
    "/users/",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.User,
    response_model_exclude={"password"},
)
async def create_user(
    user: schemas.UserCreate,
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> schemas.User:
    if superuser is None:
        raise exceptions.forbidden_exception()

    hashed_password = hashers.hasher.get_hashed_password(user.password)

    user_dict = user.dict() | {
        "password": hashed_password,
        "is_active": True,
        "is_staff": False,
        "is_superuser": False,
        "date_joined": datetime.datetime.now(),
        "last_login": None,
    }

    stmt = models.users.insert().values(**user_dict)

    try:
        return schemas.User(
            **user_dict,
            id=await Persistence(conn).insert(stmt),
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
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    user_dict = user.dict(exclude_unset=True)

    if not user_dict:
        raise exceptions.bad_request_exception()

    stmt = sa.update(models.users).where(models.users.c.id == user_id)

    try:
        user_model = await Persistence(conn).update_or_failure(
            stmt,
            user_dict,
            schemas.User,
        )
        return fastapi.encoders.jsonable_encoder(user_model)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/users/{user_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_user(
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = models.users.delete().where(models.users.c.id == user_id)
    await Persistence(conn).delete_one_or_404(stmt, "User")


@router.get(
    "/users/{user_id}/groups",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups_of_user(
    user_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = (
        sa.select(models.groups)
        .join_from(
            models.groups,
            models.user_groups,
        )
        .where(models.user_groups.c.user_id == user_id)
    )
    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)


@router.get(
    "/users/{user_id}/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.PermissionContentType],
)
async def list_permissions_of_user(
    user_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = (
        sa.select(
            models.permissions,
            models.content_types.c.app_label,
            models.content_types.c.model,
        )
        .join_from(
            models.content_types,
            models.permissions,
        )
        .join_from(
            models.permissions,
            models.user_permissions,
        )
        .where(models.user_permissions.c.user_id == user_id)
    )
    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)


@router.get(
    "/content-types",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.ContentType],
)
async def list_content_types(
    params: dict = fastapi.Depends(list_params),
    app_label: str | None = fastapi.Query(default=None, max_length=100),
    model: str | None = fastapi.Query(default=None, max_length=100),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = sa.select(models.content_types)

    if app_label:
        stmt = stmt.where(models.content_types.c.app_label == app_label)
    if model:
        stmt = stmt.where(models.content_types.c.app_label == model)

    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)


@router.get(
    "/content_types/{content_type_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.ContentType,
)
async def get_content_type(
    content_type_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = sa.select(models.content_types).where(
        models.content_types.c.id == content_type_id
    )

    return await Persistence(conn).get_one_or_404(
        stmt, schemas.ContentType.Config().title
    )


@router.post(
    "/content-types/",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.ContentType,
)
async def create_content_type(
    content_type: schemas.ContentTypeCreate,
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> schemas.ContentType:
    if superuser is None:
        raise exceptions.forbidden_exception()

    content_type_dict = content_type.dict()
    stmt = models.content_types.insert().values(**content_type_dict)

    try:
        return schemas.ContentType(
            **content_type_dict,
            id=await Persistence(conn).insert(stmt),
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
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    content_type_dict = content_type.dict(exclude_unset=True)

    if not content_type_dict:
        raise exceptions.bad_request_exception()

    stmt = sa.update(models.content_types).where(
        models.content_types.c.id == content_type_id
    )

    try:
        content_type_model = await Persistence(conn).update_or_failure(
            stmt,
            content_type_dict,
            schemas.ContentType,
        )
        return fastapi.encoders.jsonable_encoder(content_type_model)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/content-types/{content_type_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_content_type(
    content_type_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = models.content_types.delete().where(
        models.content_types.c.id == content_type_id
    )
    await Persistence(conn).delete_one_or_404(stmt, "Content Type")


@router.get(
    "/content-types/{content_type_id}/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.PermissionContentType],
)
async def list_permissions_of_content_type(
    content_type_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

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
        .where(models.content_types.c.id == content_type_id)
    )
    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)


@router.post(
    "/content-types/{content_type_id}/permissions",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.Permission,
)
async def create_permission_of_content_type(
    permission: schemas.PermissionCreate,
    content_type_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> schemas.Permission:
    if superuser is None:
        raise exceptions.forbidden_exception()

    permission_dict = permission.dict()

    if permission_dict["content_type_id"] != content_type_id:
        raise exceptions.bad_request_exception()

    stmt = models.permissions.insert().values(**permission_dict)

    try:
        return schemas.Permission(
            **permission_dict,
            id=await Persistence(conn).insert(stmt),
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
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    permission_dict = permission.dict(exclude_unset=True)

    if not permission_dict:
        raise exceptions.bad_request_exception()

    if permission_dict["content_type_id"] != content_type_id:
        raise exceptions.bad_request_exception()

    stmt = sa.update(models.permissions).where(models.permissions.c.id == permission_id)

    try:
        permission_model = await Persistence(conn).update_or_failure(
            stmt,
            permission_dict,
            schemas.Permission,
        )
        return fastapi.encoders.jsonable_encoder(permission_model)
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
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = models.permissions.delete().where(
        models.permissions.c.id == permission_id,
        models.permissions.c.content_type_id == content_type_id,
    )
    await Persistence(conn).delete_one_or_404(stmt, "Permission")


@router.get(
    "/groups",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups(
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = sa.select(models.groups).offset(params["skip"]).limit(params["take"])
    return await Persistence(conn).get_all(stmt)


@router.get(
    "/groups/{group_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.Group,
)
async def get_group(
    group_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = sa.select(models.groups).where(models.groups.c.id == group_id)
    return await Persistence(conn).get_one_or_404(stmt, schemas.Group.Config().title)


@router.post(
    "/groups/",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.Group,
)
async def create_group(
    group: schemas.GroupCreate,
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> schemas.Group:
    if superuser is None:
        raise exceptions.forbidden_exception()

    group_dict = group.dict()
    stmt = models.groups.insert().values(**group_dict)
    try:
        return schemas.Group(
            **group_dict,
            id=await Persistence(conn).insert(stmt),
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
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

    group_dict = group.dict(exclude_unset=True)

    if not group_dict:
        raise exceptions.bad_request_exception()

    stmt = sa.update(models.groups).where(models.groups.c.id == group_id)

    try:
        group_model = await Persistence(conn).update_or_failure(
            stmt,
            group_dict,
            schemas.Group,
        )
        return fastapi.encoders.jsonable_encoder(group_model)
    except sa.exc.IntegrityError:
        raise exceptions.conflict_exception()


@router.delete(
    "/groups/{group_id}",
    status_code=fastapi.status.HTTP_204_NO_CONTENT,
    response_class=fastapi.Response,
)
async def delete_group(
    group_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = models.groups.delete().where(models.groups.c.id == group_id)
    await Persistence(conn).delete_one_or_404(stmt, "Group")


@router.get(
    "/groups/{group_id}/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users_of_group(
    group_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = (
        sa.select(models.users)
        .join_from(
            models.users,
            models.user_groups,
        )
        .where(models.groups.c.id == group_id)
    )
    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)


@router.get(
    "/groups/{group_id}/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.PermissionContentType],
)
async def list_permissions_of_group(
    group_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = (
        sa.select(
            models.permissions,
            models.content_types.c.app_label,
            models.content_types.c.model,
        )
        .join_from(
            models.content_types,
            models.permissions,
        )
        .join_from(
            models.permissions,
            models.group_permissions,
        )
        .where(models.group_permissions.c.group_id == group_id)
    )
    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)


@router.post(
    "/groups/{group_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.UserGroup,
)
async def create_user_of_group(
    group_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> schemas.UserGroup:
    if superuser is None:
        raise exceptions.forbidden_exception()

    user_group_dict = {
        "user_id": user_id,
        "group_id": group_id,
    }

    stmt = models.user_groups.insert().values(**user_group_dict)

    try:
        return schemas.UserGroup(
            **user_group_dict,
            id=await Persistence(conn).insert(stmt),
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
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = models.user_groups.delete().where(
        models.user_groups.c.user_id == user_id,
        models.user_groups.c.group_id == group_id,
    )
    await Persistence(conn).delete_one_or_404(stmt, "User Group")


@router.get(
    "/permissions",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.PermissionContentType],
)
async def list_permissions(
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = sa.select(
        models.permissions,
        models.content_types.c.app_label,
        models.content_types.c.model,
    ).join_from(
        models.permissions,
        models.content_types,
    )
    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)


@router.get(
    "/permissions/{permission_id}",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=schemas.UserPermission,
)
async def get_permission(
    permission_id: int = fastapi.Query(default=0, gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> typing.Any:
    if superuser is None:
        raise exceptions.forbidden_exception()

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

    return await Persistence(conn).get_one_or_404(
        stmt, schemas.Permission.Config().title
    )


@router.get(
    "/permissions/{permission_id}/users",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.User],
    response_model_exclude={"password"},
)
async def list_users_of_permission(
    params: dict = fastapi.Depends(list_params),
    permission_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = (
        sa.select(models.users)
        .join_from(
            models.users,
            models.user_permissions,
        )
        .where(models.user_permissions.c.permission_id == permission_id)
    )
    stmt = stmt.offset(params["skip"]).limit(params["take"])
    return await Persistence(conn).get_all(stmt)


@router.get(
    "/permissions/{permission_id}/groups",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.Group],
)
async def list_groups_of_permission(
    permission_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = (
        sa.select(models.groups)
        .join_from(
            models.groups,
            models.group_permissions,
        )
        .where(models.permissions.c.permission_id == permission_id)
    )
    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)


@router.post(
    "/permissions/{permission_id}/users/{user_id}",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.UserPermission,
)
async def create_permission_of_user(
    permission_id: int = fastapi.Query(gt=0),
    user_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> schemas.UserPermission:
    if superuser is None:
        raise exceptions.forbidden_exception()

    user_permission_dict = {
        "permission_id": permission_id,
        "user_id": user_id,
    }

    stmt = models.user_permissions.insert().values(**user_permission_dict)

    try:
        return schemas.UserPermission(
            **user_permission_dict,
            id=await Persistence(conn).insert(stmt),
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
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = models.user_permissions.delete().where(
        models.user_permissions.c.user_id == user_id,
        models.user_permissions.c.permission_id == permission_id,
    )
    await Persistence(conn).delete_one_or_404(stmt, "User Permission")


@router.post(
    "/permissions/{permission_id}/group/{group_id}",
    status_code=fastapi.status.HTTP_201_CREATED,
    response_model=schemas.GroupPermission,
)
async def create_permission_of_group(
    permission_id: int = fastapi.Query(gt=0),
    group_id: int = fastapi.Query(gt=0),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> schemas.GroupPermission:
    if superuser is None:
        raise exceptions.forbidden_exception()

    group_permission_dict = {
        "permission_id": permission_id,
        "group_id": group_id,
    }

    stmt = models.group_permissions.insert().values(**group_permission_dict)

    try:
        return schemas.GroupPermission(
            **group_permission_dict,
            id=await Persistence(conn).insert(stmt),
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
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> None:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = models.group_permissions.delete().where(
        models.group_permissions.c.group_id == group_id,
        models.group_permissions.c.permission_id == permission_id,
    )
    await Persistence(conn).delete_one_or_404(stmt, "Group Permission")


@router.get(
    "/permissions/{permission_id}/content-types",
    status_code=fastapi.status.HTTP_200_OK,
    response_model=list[schemas.ContentType],
)
async def list_content_types_of_permission(
    permission_id: int = fastapi.Query(gt=0),
    params: dict = fastapi.Depends(list_params),
    superuser: dict = fastapi.Depends(authentication.get_superuser),
    conn: sa.ext.asyncio.engine.AsyncConnection = fastapi.Depends(engine_connect),
) -> list[typing.Any]:
    if superuser is None:
        raise exceptions.forbidden_exception()

    stmt = (
        sa.select(models.content_types)
        .join_from(
            models.content_types,
            models.permissions,
        )
        .where(models.permissions.c.id == permission_id)
    )
    stmt = stmt.offset(params["skip"]).limit(params["take"])

    return await Persistence(conn).get_all(stmt)
