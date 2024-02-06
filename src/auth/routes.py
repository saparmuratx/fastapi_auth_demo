from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

from pymongo.errors import DuplicateKeyError
import icecream


from src.database import users

from .schemas import UserRegister, Token
from .auth import (
    check_username,
    get_password_hash,
    get_user,
    verify_password,
    create_access_token,
    decode_token,
)

from .utils import credentials_exception


auth_router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_active_user(token: Annotated[str, Depends(oauth2_scheme)]):
    icecream.ic(token)

    payload = decode_token(token)

    user = get_user(payload.get("sub"))

    if not user:
        raise credentials_exception

    return user


@auth_router.post("/register", tags=["auth"])
async def register(data: UserRegister = Body(...)):
    if not check_username(data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is already in use",
        )

    if data.password != data.password2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords don't match",
        )

    hashed_password = get_password_hash(data.password)

    try:
        users.insert_one(
            {"username": data.username, "hashed_password": hashed_password}
        )

    except DuplicateKeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is already in use",
        )

    return {"message": "User successfully registered"}


@auth_router.post("/token", tags=["auth"])
async def get_token(form: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = get_user(form.username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(form.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username},
    )

    return Token(access_token=access_token, token_type="bearer")
