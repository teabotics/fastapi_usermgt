from datetime import datetime

import pytz
from sqlalchemy import func, text, or_, and_
from sqlalchemy.orm import Session
from database import engine

import models
import schemas


def get_acct(db: Session, acct_id: int) -> models.Account:
    return db.query(models.Account).filter(models.Account.id == acct_id).first()


def get_acct_by_email_and_idp(db: Session, email: str, idp: str = schemas.Idp.LOCAL) -> models.Account:
    return db.query(models.Account).filter(and_(models.Account.email == email), (models.Account.idp == idp)).first()


def get_acct_by_email(db: Session, email: str) -> models.Account:
    return db.query(models.Account).filter(models.Account.email == email).first()


def get_acct_by_username_and_idp(db: Session, username: str, idp: str = schemas.Idp.LOCAL) -> models.Account:
    return db.query(models.Account).filter(and_(models.Account.username == username), (models.Account.idp == idp)).first()


def get_acct_by_username(db: Session, username: str) -> models.Account:
    return db.query(models.Account).filter(models.Account.username == username).first()


def get_acct_by_social_id(db: Session, social_id: str) -> models.Account:
    return db.query(models.Account).filter(models.Account.social_id == social_id).first()


def get_accts(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Account).order_by(models.Account.id).offset(skip).limit(limit).all()


def get_acct_count(db: Session):
    return db.query(models.Account).count()


def get_session_accts_today(db: Session):
    # 查詢每天有幾個user有登入/操作系統
    return db.query(models.Account).filter(text("current_date = date(last_session_time)")).count()


def get_avg_session_accts_7_days(db: Session):
    # 查詢過去7天，每天平均有幾個user有登入/操作系統
    sql = text(f'select (sum(count(distinct owner_id)) over())/7 the_answer from records where date(session_time) >= (current_date-6) and date(session_time) <= (current_date) group by date(session_time)')
    result = engine.connect().execute(sql)
    value_list = [row[0] for row in result]
    value = '{:.2f}'.format(value_list[0])
    return value


def update_acct(db: Session,
                acct_id: int = None,
                email: str = None,
                update_login_count=False,
                update_last_session_time=False,
                update_last_login_time=False,
                set_activate=False,
                password=None,
                username=None):
    db_acct = None
    if acct_id:
        db_acct = get_acct(db, acct_id)
    elif email:
        db_acct = get_acct_by_email(db, email)
    else:
        return None

    if db_acct:
        now = pytz.timezone('Asia/Taipei').localize(datetime.now())
        db_record = None
        if update_login_count:
            db_acct.login_count += 1
        if update_last_session_time:
            db_acct.last_session_time = now
            if not db_record:
                db_record = models.Record(owner_id=db_acct.id)
            db_record.session_time = now
        if update_last_login_time:
            db_acct.last_login_time = now
            if not db_record:
                db_record = models.Record(owner_id=db_acct.id)
            db_record.login_time = now
        if password:
            db_acct.hashed_password = password
        if username:
            db_acct.username = username
        if set_activate:
            db_acct.is_active = True

        db.merge(db_acct)
        db.commit()
        db.refresh(db_acct)

        db.add(db_record)
        db.commit()
        db.refresh(db_record)
    else:
        print('cannot find account')
        db_acct = None

    return db_acct


def create_acct(db: Session, acct: schemas.AccountCreate) -> models.Account:
    now = pytz.timezone('Asia/Taipei').localize(datetime.now())
    db_acct = models.Account(username=acct.username,
                             email=acct.email,
                             hashed_password=acct.password,
                             idp=acct.idp,
                             sign_up_time=now,
                             social_id=acct.social_id,
                             login_count=0,
                             is_active=acct.is_active)
    db.add(db_acct)
    db.commit()
    db.refresh(db_acct)
    return db_acct


def get_records(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Record).offset(skip).limit(limit).all()


def create_user_record(db: Session, record: schemas.RecordCreate, acct_id: int):
    db_record = models.Record(**record.dict(), owner_id=acct_id)
    db.add(db_record)
    db.commit()
    db.refresh(db_record)
    return db_record