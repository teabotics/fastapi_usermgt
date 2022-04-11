from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from database import Base
from schemas import Idp


class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    email = Column(String, index=True)
    idp = Column(String, default=Idp.LOCAL)  # local是在自己資料庫註冊的，auth0是透過auth0做auth的帳號
    social_id = Column(String)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=False)
    sign_up_time = Column(DateTime)
    login_count = Column(Integer)
    last_login_time = Column(DateTime)
    last_session_time = Column(DateTime)
    records = relationship("Record", back_populates="owner")

    def to_dict(self, hide_sensitive_data: bool = True) -> dict:
        dict_out = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'idp': self.idp,
            'social_id': self.social_id,
            'is_active': self.is_active,
            'sign_up_time': self.sign_up_time.strftime("%Y-%m-%d %H:%M:%S") if self.sign_up_time else None,
            'login_count': self.login_count,
            'last_login_time': self.last_login_time.strftime("%Y-%m-%d %H:%M:%S") if self.last_login_time else None,
            'last_session_time': self.last_session_time.strftime(
                "%Y-%m-%d %H:%M:%S") if self.last_session_time else None,
        }
        if not hide_sensitive_data:
            dict_out['hashed_password'] = self.hashed_password

        return dict_out


class Record(Base):
    __tablename__ = "records"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("accounts.id"))
    login_time = Column(DateTime)
    session_time = Column(DateTime)
    owner = relationship("Account", back_populates="records")

    def to_dict(self):
        return {
            'id': self.id,
            'owner_id': self.owner_id,
            'login_time': self.login_time.strftime("%Y-%m-%d %H:%M:%S") if self.login_time else None,
            'session_time': self.session_time.strftime("%Y-%m-%d %H:%M:%S") if self.session_time else None,
        }
