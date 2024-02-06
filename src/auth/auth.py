from datetime import timedelta, timezone, datetime

from jose import jwt, JWTError
from passlib.context import CryptContext

from src.database import users
from src.config import settings

from .schemas import UserInDB
from .utils import credentials_exception


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(plain_password: str):
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def check_username(username: str):
    user = users.find_one({"username": username})

    return user is None


def get_user(username):
    user = users.find_one({"username": username}, {"_id": 0})

    if user:
        return UserInDB(**user)
    else:
        return False


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )

    return encoded_jwt


def decode_token(token: str):
    print("1!" * 5)

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, settings.JWT_ALGORITHM)

        username = payload.get("sub")

        if username is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    print("2!" * 5)

    return payload
