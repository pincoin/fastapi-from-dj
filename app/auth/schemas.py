from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    is_superuser: bool = False
    username: str = Field(max_length=150)
    first_name: str = Field(max_length=150)
    last_name: str = Field(max_length=150)
    email: EmailStr
    is_staff: bool = False
    is_active: bool = True


class UserOut(UserBase):
    last_login: datetime | None = None
    date_joined: datetime


class UserIn(UserBase):
    password: str = Field(max_length=128)
