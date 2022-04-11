from datetime import datetime
from typing import List

from pydantic import BaseModel


class Idp:
    LOCAL = "LOCAL"
    SOCIAL = "SOCIAL"


class RecordBase(BaseModel):
    login_time: datetime | None = None
    session_time: datetime | None = None


class RecordCreate(RecordBase):
    pass


class Record(RecordBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True


class AccountBase(BaseModel):
    email: str
    username: str | None = None
    idp: str = Idp.LOCAL  # Identity Provider
    social_id: str | None = None
    is_active: bool = False


class AccountCreate(AccountBase):
    password: str | None = None


class Account(AccountBase):
    id: int
    sign_up_time: datetime | None = None
    login_count: int | None = None
    last_login_time: datetime | None = None
    last_session_time: datetime | None = None
    records: List[Record] = []

    class Config:
        orm_mode = True


class AccountUpdate(AccountCreate):
    old_password: str | None = None


class AccountInDB(Account):
    hashed_password: str


# class Token(BaseModel):
#     access_token: str
#     token_type: str
#
#
# class TokenData(BaseModel):
#     username: str | None = None



