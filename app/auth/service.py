from datetime import timedelta
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models import User
from app.schemas import UserCreate, UserLogin, Token
from app.auth.utils import hash_password, verify_password, create_token
from app.config import settings

def register_user(db: Session, user: UserCreate) -> User:
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = User(
        username=user.username,
        hashed_password=hash_password(user.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user

def authenticate_user(db: Session, credentials: UserLogin) -> Token:
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_token({"sub": user.username}, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": user.username}, timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))

    return Token(access_token=access_token, refresh_token=refresh_token)
