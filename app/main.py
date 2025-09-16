import os
from datetime import datetime, timedelta, timezone
from typing import Annotated
import jwt
import app.schemas as schemas
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from contextlib import asynccontextmanager
from app.database import create_all_tables, dispose_engine, get_db
from app import models
from sqlalchemy.orm import Session
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
# to get a string like this run:
# openssl rand -hex 32

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables
    create_all_tables()
    yield
    # Shutdown: dispose engine and close all connections
    dispose_engine()

app = FastAPI(lifespan=lifespan)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    if user:
        return schemas.UserInDB(**user.__dict__)
    return None


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)],
                           db: Annotated[Session, Depends(get_db)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[schemas.User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        db: Annotated[Session, Depends(get_db)]
) -> schemas.Token:
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return schemas.Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(
    current_user: Annotated[schemas.User, Depends(get_current_active_user)],
):
    return current_user


@app.get("/users", response_model=list[schemas.User])
async def list_users(current_user: Annotated[schemas.User, Depends(get_current_active_user)],
                    db: Annotated[Session, Depends(get_db)]):
    users = db.query(models.User).order_by(models.User.id.asc()).all()
    return users


@app.post("/users", response_model=str, status_code=status.HTTP_201_CREATED)
async def create_user_endpoint(
    payload: schemas.UserCreate,
    db: Annotated[Session, Depends(get_db)],
    ):
    existing_user_by_username = (
        db.query(models.User).filter(models.User.username == payload.username).first()
    )
    if existing_user_by_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    # Check for existing email
    existing_user_by_email = (
        db.query(models.User).filter(models.User.email == payload.email).first()
    )
    if existing_user_by_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    hashed_password = get_password_hash(payload.password)

    new_user = models.User(
        username=payload.username,
        full_name=payload.full_name,
        hashed_password=hashed_password,
        email=payload.email,
        disabled=payload.disabled,
    )
    db.add(new_user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    db.refresh(new_user)

    # Return without hashed_password per response_model
    return f"{payload.username} have been created"
