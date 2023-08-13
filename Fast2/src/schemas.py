from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, EmailStr



class AccountSchema(BaseModel): # noqa
    username: str = Field(min_length=5, max_length=16)
    email: EmailStr
    password: str = Field(min_length=6, max_length=10)


class AccountResponseSchema(BaseModel):
    id: int
    username: str
    email: str
    avatar: str

    class Config:
        from_attributes = True


class TokenModel(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserSchema(BaseModel):
    first_name: str = Field(max_length=50, min_length=3)
    last_name: str = Field(max_length=50, min_length=3)
    email: str = Field(max_length=30, min_length=5)
    phone_number: str = Field(max_length=30, min_length=5)
    birthday: str = Field(max_length=30, min_length=8)
    data: Optional[bool] = False


class UserUpdateSchema(UserSchema):
    data: bool


class UserResponse(BaseModel):
    id: int = 1
    first_name: str
    last_name: str
    email: str
    phone_number: str
    birthday: str
    data: bool
    created_at: datetime | None
    updated_at: datetime | None
    acc: AccountResponseSchema | None

    class Config:
        from_attributes = True # noqa