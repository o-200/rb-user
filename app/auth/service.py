from datetime import timedelta
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models import User, Token
from app.schemas import UserCreate, UserLogin
from app.auth.utils import hash_password, verify_password, create_token
from app.config import settings

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer

def register_user(db: Session, user: UserCreate) -> User:
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    new_user = User(
        username=user.username,
        email=user.email,
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

    existing_token = (
        db.query(Token)
          .filter(Token.user_id == user.id, Token.is_valid == True)
          .order_by(Token.created_at.desc())
          .first()
    )

    if existing_token:
        return existing_token

    access_token = create_token({"sub": user.username}, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token({"sub": user.username}, timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))

    new_token = Token(
        access_token=access_token,
        refresh_token=refresh_token,
        user_id=user.id
    )

    db.add(new_token)
    db.commit()
    db.refresh(new_token)

    return new_token


def invalidate_user(db: Token, token: str) -> Token:
    token = db.query(Token).filter(Token.access_token == token).first()
    if token:
        token.is_valid = False
        db.commit()
        return Token
    else:
        raise HTTPException(status_code=404, detail="Token doesn't exists")
    
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
def verify_token(db: Token, token: str = Depends(oauth2_scheme)) -> str:
    token = db.query(Token).filter_by(access_token=token, is_valid=True).first()
    return token is not None