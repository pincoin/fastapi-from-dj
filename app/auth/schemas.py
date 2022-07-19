import datetime

from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    username: str = Field(max_length=150)
    first_name: str = Field(max_length=150)
    last_name: str = Field(max_length=150)
    email: EmailStr
    password: str = Field(max_length=128)


class UserUpdate(BaseModel):
    first_name: str | None = Field(max_length=150)
    last_name: str | None = Field(max_length=150)
    email: EmailStr | None = None
    password: str | None = Field(max_length=128)
    is_active: bool | None = False
    is_staff: bool | None = False
    is_superuser: bool | None = False


class User(BaseModel):
    id: int | None
    username: str
    first_name: str
    last_name: str
    email: EmailStr
    password: str
    is_active: bool | None = False
    is_staff: bool | None = False
    is_superuser: bool | None = False
    last_login: datetime.datetime | None = None
    date_joined: datetime.datetime

    class Config:
        title = "User"


class GroupUpdate(BaseModel):
    name: str | None = Field(max_length=150)


class GroupCreate(GroupUpdate):
    name: str = Field(max_length=150)


class Group(GroupCreate):
    id: int | None

    class Config:
        title = "Group"


class ContentTypeUpdate(BaseModel):
    app_label: str | None = Field(max_length=100)
    model: str | None = Field(max_length=100)


class ContentTypeCreate(ContentTypeUpdate):
    app_label: str = Field(max_length=100)
    model: str = Field(max_length=100)


class ContentType(ContentTypeCreate):
    id: int | None

    class Config:
        title = "Content Type"


class PermissionUpdate(BaseModel):
    content_type_id: int
    name: str | None = Field(max_length=255)
    codename: str | None = Field(max_length=100)


class PermissionCreate(PermissionUpdate):
    name: str = Field(max_length=255)
    codename: str = Field(max_length=100)


class Permission(PermissionCreate):
    id: int | None

    class Config:
        title = "Permission"


class PermissionContentType(Permission, ContentType):
    id: int | None


class UserGroup(BaseModel):
    id: int | None
    user_id: int
    group_id: int

    class Config:
        title = "User Group"


class UserPermission(BaseModel):
    id: int | None
    user_id: int
    permission_id: int

    class Config:
        title = "User Permission"


class GroupPermission(BaseModel):
    id: int | None
    group_id: int
    permission_id: int

    class Config:
        title = "Group Permission"


class RefreshToken(BaseModel):
    refresh_token: str
    token_type: str


class Token(BaseModel):
    id: int | None
    user_id: int
    token: str
    expiration_time_delta: datetime.timedelta
    created: datetime.datetime

    class Config:
        title = "OAuth2 Token"
