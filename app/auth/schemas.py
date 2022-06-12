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
    id: int
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
