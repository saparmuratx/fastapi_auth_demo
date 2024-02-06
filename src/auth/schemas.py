from pydantic import BaseModel, field_validator


class UserRegister(BaseModel):
    username: str
    password: str
    password2: str

    @field_validator("username")
    @classmethod
    def username_validator(cls, v: str):
        if v == "":
            raise ValueError("username may not be blank")

        if str(v[0]).isdigit():
            raise ValueError("username should not start with digit")

        return v.title()


class UserInDB(BaseModel):
    username: str
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str
