from datetime import datetime

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
    last_login: datetime | None = None
    date_joined: datetime


class GroupCreate(BaseModel):
    name: str = Field(max_length=150)


class GroupUpdate(BaseModel):
    name: str | None = Field(max_length=150)


class Group(GroupCreate):
    id: int | None


class ContentTypeCreate(BaseModel):
    app_label: str = Field(max_length=100)
    model: str = Field(max_length=100)


class ContentTypeUpdate(BaseModel):
    app_label: str | None = Field(max_length=100)
    model: str | None = Field(max_length=100)


class ContentType(ContentTypeCreate):
    id: int | None


class PermissionCreate(BaseModel):
    name: str = Field(max_length=255)
    codename: str = Field(max_length=100)


class PermissionUpdate(BaseModel):
    name: str | None = Field(max_length=255)
    codename: str | None = Field(max_length=100)


class Permission(PermissionCreate):
    id: int | None
