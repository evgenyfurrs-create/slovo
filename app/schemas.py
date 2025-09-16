from pydantic import BaseModel, Field


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str = Field(max_length=50)
    email: str | None = None
    full_name: str | None = None
    disabled: bool = True


class UserInDB(User):
    hashed_password: str

class UserCreate(User):
    password: str