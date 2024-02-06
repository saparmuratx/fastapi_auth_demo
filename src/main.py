from typing import Annotated

from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer

import icecream

from src.config import settings

from src.auth.routes import auth_router, get_current_active_user
from src.auth.schemas import UserInDB

app = FastAPI()

app.include_router(auth_router)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.get("/api/home")
async def home():
    return {"message": "Test message in home!"}


@app.get("/")
async def root():
    return {"message": settings}


@app.get("/items")
async def read_items(
    user: Annotated[UserInDB, Depends(get_current_active_user)],
):
    return user


@app.get("/profile")
async def get_profile(token: Annotated[str, Depends(get_current_active_user)]):
    return {"data": token}
