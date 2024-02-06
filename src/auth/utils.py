from fastapi.exceptions import HTTPException
from fastapi import status

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid authentication credentials.",
    headers={"WWW-Authenticate": "Bearer"},
)
