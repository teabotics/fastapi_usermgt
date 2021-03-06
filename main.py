import os
import re
from datetime import datetime, timedelta

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from sqlalchemy.orm import Session
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse, Response

import crud
import models
import schemas
from database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)
load_dotenv()

# password hash
LOCAL_SECRET_KEY = os.getenv('LOCAL_SECRET_KEY')
LOCAL_JWT_ALGORITHM = os.getenv('LOCAL_JWT_ALGORITHM')
# expire in 3 days
LOCAL_ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv('LOCAL_ACCESS_TOKEN_EXPIRE_MINUTES')

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/accounts/token")

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=LOCAL_SECRET_KEY)

origins = [
    "https://usermgt-front.herokuapp.com",
    "https://fastapi-usermgt.herokuapp.com",
    "http://localhost:8000",
    "http://localhost:4200",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_access_token_from_header(request: Request) -> str:
    token_str = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith('Bearer '):
        token_str = auth_header.split()[1]
    return token_str


def authenticate_acct(db: Session, email: str, pwd: str = None, idp: str = schemas.Idp.LOCAL) -> dict:
    acct_dict = None
    if email:
        acct_model = crud.get_acct_by_email(db, email=email)
        if acct_model:
            acct_dict = acct_model.to_dict(hide_sensitive_data=False)
            # ????????????access_token?????????????????????????????????pwd??????????????????????????????
            # ?????????login form????????????????????????pwd?????????????????????pwd?????????
            if pwd and not verify_password(pwd, acct_dict['hashed_password']):
                acct_dict = None
    return acct_dict


def validate_local_access_token(token_str: str) -> dict:
    payload = None
    print('validate_local_access_token....')
    try:
        payload = jwt.decode(token_str, LOCAL_SECRET_KEY, algorithms=[LOCAL_JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        print("Token expired.")
    except JWTError:
        print("Token error")
    return payload


def validate_auth0_access_token(token_str: str) -> dict:
    payload = None
    print('validate_auth0_access_token....')
    # ???aut0???user profile????????????????????????token??????

    headers = {'Authorization': f'Bearer {token_str}'}
    response = httpx.get(f'https://{os.getenv("AUTH0_DOMAIN")}/userinfo', headers=headers)
    if response.status_code != 200:
        return payload  # ??????token????????????auth0????????????
    else:
        profile_data = response.json()
        payload = {'sub': profile_data['email'], 'name': profile_data['name'], 'social_id': profile_data['sub']}
    return payload


def get_payload_from_req_header(request: Request):
    token = get_access_token_from_header(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = validate_local_access_token(token)
    if not payload:
        payload = validate_auth0_access_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, LOCAL_SECRET_KEY, algorithm=LOCAL_JWT_ALGORITHM)
    return encoded_jwt


async def sendemail(request: Request, acct_dict: dict):
    # using SendGrid's Python Library# https://github.com/sendgrid/sendgrid-python

    access_token_expires = timedelta(minutes=int(LOCAL_ACCESS_TOKEN_EXPIRE_MINUTES))
    activate_access_token = create_access_token(
        data={"sub": acct_dict['email']},
        expires_delta=access_token_expires
    )

    emailbox = os.getenv('SEND_TO_TEST_EMAIL_BOX')
    if not emailbox:
        emailbox = acct_dict['email']

    message = Mail(
        from_email='sendergrid@teabotics.com',
        to_emails=emailbox,
        subject='Activate your account!!',
        html_content=f'''<strong>Click the following link to activate your account!!</strong><br>
        <a href="https://fastapi-usermgt.herokuapp.com/accounts/activate?activatestr={activate_access_token}" target="_blank" >Click me!!</a>'''
    )
    try:
        sg = SendGridAPIClient(os.getenv('SENDGRID_KEY'))
        response = sg.send(message)
        # print(response.status_code)
        # print(response.body)
        # print(response.headers)
    except Exception as e:
        print(e)
    # ?????????????????????????????????


def authenticate(payload: dict = Depends(get_payload_from_req_header),
                 db: Session = Depends(get_db)) -> dict:
    # payload = get_payload_from_req_header(request)
    acct_autheticated = authenticate_acct(db=db, email=payload['sub'])
    if not acct_autheticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account doesn't exist",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {'payload': payload, 'acct_dict': acct_autheticated}


@app.get("/accounts/acctstat", summary="Retrieve user statistics", response_description="User statistics")
def get_acctstat(auth_result: dict = Depends(authenticate), db: Session = Depends(get_db)):
    """
    Retrieve user statistics:

    Required request parameters. (http Authorization request header)
    - Athorization token

    Response:
    - **acct_count**: Total number of users who have signed up.
    - **session_accts_today**: Total number of users with active sessions today.
    - **avg_session_accts_7_days**: Average number of active session users in the last 7 days rolling.

    """
    db_acct = crud.update_acct(db=db,
                               email=auth_result['payload']['sub'],
                               update_last_session_time=True
                               )

    return {"session_accts_today": crud.get_session_accts_today(db),
            "acct_count": crud.get_acct_count(db),
            "avg_session_accts_7_days": crud.get_avg_session_accts_7_days(db)
            }


@app.post("/accounts/registersocial", response_model=schemas.AccountBase,
          summary="Register an account for google or facebook",
          response_description="Registered account info")
async def create_social_acct(request: Request,
                             acct_create: schemas.AccountBase,
                             db: Session = Depends(get_db)):
    """
    Register an account for people who login with google or facebook account:

    This API is called by web front everytime a user logged in with social account. The program will check
    if the social account has been registered in the system. If not, the program will register the user. If the
    social account has been registered before, it will not be registered again.

    The email have to be unique, therefore, if the email of the social account has existed in the system, the
    registration of the social account will fail.

    Required request parameters. (http Authorization request header)
    - Athorization token provided by Auth0

    Required request parameters. (http request body)
    - **email**: email of the social account
    - **username**: user name of the social account
    - **social_id**: The 'sub' value of user info provided by Auth0

    Response:
    - account info of registered social account

    """
    payload = get_payload_from_req_header(request)
    db_acct = crud.get_acct_by_email(db, email=acct_create.email)
    if db_acct:
        # ?????????????????????email???account???social id????????????????????????????????????????????????user???????????????
        if db_acct.social_id == payload['social_id']:
            # ????????????function??????user???UI???????????????????????????????????????????????????????????????login time???session time
            db_acct_updated = crud.update_acct(db=db,
                                               email=db_acct.email,
                                               update_last_login_time=True,
                                               update_last_session_time=True,
                                               update_login_count=True
                                               )
            # ?????????????????????????????????????????????????????????
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=jsonable_encoder(schemas.AccountBase(**db_acct.to_dict()))
            )
        if not db_acct.social_id == payload['social_id']:
            # ??????social id?????????????????????????????????local????????????social????????????????????????email???
            # print('different social_id')
            raise HTTPException(status_code=403, detail="Email already registered")
    else:
        registered_acct = crud.create_acct(
            db=db,
            acct=schemas.AccountCreate(
                username=acct_create.username,
                email=acct_create.email,
                password='social',
                idp=schemas.Idp.SOCIAL,
                social_id=acct_create.social_id,
                is_active=True
            )
        )
        # ?????????social account???????????????active????????????login???update
        registered_acct_updated = crud.update_acct(db=db,
                                                   email=registered_acct.email,
                                                   update_login_count=True,
                                                   update_last_login_time=True,
                                                   update_last_session_time=True
                                                   )

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=jsonable_encoder(schemas.AccountBase(**registered_acct_updated.to_dict()))
        )


@app.post("/accounts/register", response_model=schemas.AccountBase,
          summary="Register an local account",
          response_description="Registered account info"
          )
async def create_acct(request: Request,
                      acct_create: schemas.AccountCreate,
                      db: Session = Depends(get_db)):
    """
    Register an account in the system:

    An account created in the system directly is defined as a "Local account". Not like facebook or google, all
    the account info of a local account are hold by our own system, not any 3rd party identity provider.

    This API is called by web front register form.

    After the account is registered, an activation email will be sent to user's email box, user can click the
    activation link in the email to activate the account. A not-activated local account cannot log into system.

    Required request parameters. (http request body)
    - **email**: email of the local account to be created
    - **username**: user name of the local account to be created
    - **password**: password of the local account to be created

    Response:
    - account info of registered local account
    """
    # check if email already taken
    db_acct = crud.get_acct_by_email(db, email=acct_create.email)
    if db_acct:
        raise HTTPException(status_code=400, detail="Email already registered")

    # check if username already taken
    # db_acct_by_name = crud.get_acct_by_username(db, username=acct_create.username)
    # if db_acct_by_name:
    #     raise HTTPException(status_code=400, detail="Username already registered")

    # validate email address
    if not is_valid_email(acct_create.email):
        raise HTTPException(status_code=400, detail="email format is not valid")

    # validate password
    if not is_valid_password(acct_create.password):
        raise HTTPException(status_code=400, detail="password format is not valid")

    registered_acct = crud.create_acct(
        db=db,
        acct=schemas.AccountCreate(
            username=acct_create.username,
            password=get_password_hash(acct_create.password),
            email=acct_create.email
        )
    )
    if registered_acct:
        await sendemail(request, registered_acct.to_dict())

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        # ?????????dict????????????AccountBase??????pydantic model, ??????account base?????????????????????????????????????????????
        # jsonable_encoder???????????????model??????????????????????????????????????????datetime???????????????????????????????????????????????????encoder??????????????????
        content=jsonable_encoder(schemas.AccountBase(**registered_acct.to_dict()))
    )


@app.get("/accounts/activate", summary="Activate a local account",
          response_description="Redirect to login page")
async def activate_acct(activatestr: str, db: Session = Depends(get_db)):
    """
    Activate a local account:

    This API is called by clicking the activation link in the email sent by the system

    Required request parameters. (http request body)
    - **activatestr**: the activate token created by register process

    Response:
    - redirect to login page
    """

    token_payload = validate_local_access_token(activatestr)

    if not token_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    acct_dict = authenticate_acct(db=db, email=token_payload.get('sub'))

    if not acct_dict:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not registered",
            headers={"WWW-Authenticate": "Bearer"},
        )

    db_acct = crud.update_acct(db=db,
                               acct_id=acct_dict['id'],
                               update_last_session_time=True,
                               set_activate=True
                               )

    return RedirectResponse(url=os.getenv('REDIRECT_AFTER_ACTIVATED')+'?username='+db_acct.username,
                            status_code=status.HTTP_302_FOUND)


@app.post("/accounts/resendemail", response_model=schemas.AccountCreate,
          summary="Resend activation/verification email",
          response_description="Account info which ask for resending email"
          )
async def resend_verification_email(
        request: Request,
        account_to_resend_email: schemas.AccountCreate,
        db: Session = Depends(get_db)
):
    """
    Resend a verification email:

    This API is called when user tried to login with a not-activated account, and click the
    "Resend Verification Email" button.

    Required request parameters. (http request body)
    - **email**: email of the account
    - **password**: password of the account

    Response:
    - Account info which ask for resending email
    """
    acct_dict = authenticate_acct(db=db, email=account_to_resend_email.email, pwd=account_to_resend_email.password)

    if not acct_dict:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    db_acct = crud.update_acct(db=db,
                               email=account_to_resend_email.email,
                               update_last_session_time=True
                               )
    await sendemail(request, acct_dict)

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=jsonable_encoder(schemas.AccountBase(**acct_dict))
    )


@app.post("/accounts/profile",
          summary="Retrieve account info of a single account",
          response_description="The account info"
          )
async def get_profile(request: Request,
                      auth_result: dict = Depends(authenticate),
                      db: Session = Depends(get_db)):
    """
    Retrieve info of an account:

    The program will extract data from JWT access token in the request header and retrieve account info accordingly.

    Required request parameters. (http Authorization request header)
    - Athorization token

    Response:
    - retrieved account info

    """

    db_acct = crud.update_acct(db=db,
                               acct_id=auth_result['acct_dict']['id'],
                               update_last_session_time=True
                               )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=jsonable_encoder(schemas.Account(**db_acct.to_dict()))
    )


@app.post("/accounts/token",
          summary="Login with a local account",
          response_description="The info of logged in account"
          )
async def login_for_access_token(response: Response,
                                 db: Session = Depends(get_db),
                                 form_data: OAuth2PasswordRequestForm = Depends()):
    """
   Login with a local account :

   An account created in the system directly is defined as a "Local account". Not like facebook or google, all
   the account info of a local account are hold by our own system, not any 3rd party identity provider.

   This API is called by web front login form.

   Required request parameters. (http request body)
   - **email**: email of the local account to login
   - **password**: password of the local account to login

   Response:
   - **access_token**: JWT token
   - **token_type**: type of token
   - **username**: user name of the logged in account
   - **email**: email of the logged in account
   """
    acct_dict = authenticate_acct(db, form_data.username, form_data.password)
    if not acct_dict:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not acct_dict['is_active']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not activated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": acct_dict['email']},
        expires_delta=timedelta(minutes=int(LOCAL_ACCESS_TOKEN_EXPIRE_MINUTES))
    )

    db_acct = crud.update_acct(db=db,
                               acct_id=acct_dict['id'],
                               update_login_count=True,
                               update_last_login_time=True,
                               update_last_session_time=True
                               )

    return {"access_token": access_token,
            "token_type": "bearer",
            "username": acct_dict['username'],
            "email": acct_dict['email']
            }


@app.get("/accounts/",
         summary="Retrieve all account info",
         response_description="The info of all accounts in the system")
def read_users(skip: int = 0,
               limit: int = 100,
               auth_result: dict = Depends(authenticate),
               db: Session = Depends(get_db)):
    """
    Retrieve info of all accounts in the system:

    This API is called by dashboard page of web front.

    Required request parameters. (http Authorization request header)
    - Athorization token

    Response:
    - a list of retrieved account info

    """

    db_acct = crud.update_acct(db=db,
                               email=auth_result['payload']['sub'],
                               update_last_session_time=True
                               )
    accts = crud.get_accts(db, skip=skip, limit=limit)

    # ????????????UI????????????model??????dict???date?????????????????????????????????
    acct_dicts = []
    for acct in accts:
        acct_dicts.append(acct.to_dict())
    return acct_dicts


@app.put("/accounts/update",
         summary="Update local account user name and/or password",
         response_description="The info of updated local account"
         )
def update_username_password(account_to_update: schemas.AccountUpdate,
                             auth_result: dict = Depends(authenticate),
                             db: Session = Depends(get_db)):
    """
    Update local account user name and/or password:

    This API is called by "Edit username and password" function of web front.

    Required request parameters. (http Authorization request header)
    - Athorization token

    Required request parameters. (http request body)
   - **username**: new user name of the local account to update
   - **password**: new password of the local account to update
   - **old_password**: old password of the local account to update

    Response:
    - updated account info

    """

    acct_dict = None
    db_acct = None
    if account_to_update.password and account_to_update.old_password:
        # ??????????????????password
        acct_dict = authenticate_acct(db=db, email=account_to_update.email, pwd=account_to_update.old_password)
        if not acct_dict:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        db_acct = crud.update_acct(db=db,
                                   acct_id=acct_dict['id'],
                                   username=account_to_update.username,
                                   password=get_password_hash(account_to_update.password),
                                   update_last_session_time=True
                                   )
    else:
        acct_dict = auth_result['acct_dict']
        db_acct = crud.update_acct(db=db,
                                   acct_id=acct_dict['id'],
                                   username=account_to_update.username,
                                   update_last_session_time=True
                                   )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=jsonable_encoder(schemas.Account(**db_acct.to_dict()))
    )

@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    return FileResponse("favicon.ico")


def is_valid_email(email: str):
    # regex_for_email = re.compile(r'^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$')
    regex_for_email = re.compile(
        '^(?:[a-z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&\'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\\])$')
    if re.fullmatch(regex_for_email, email):
        return True
    else:
        return False


def is_valid_password(password: str):
    regex_for_password = re.compile(
        r'^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[*.!@$%^&(){}\[\]:;<>,.?/~_+\-=|\\]).{8,}$')
    if re.fullmatch(regex_for_password, password):
        return True
    else:
        return False


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000)
