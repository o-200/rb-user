from datetime import timedelta
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models import User, Token
from app.schemas import UserCreate, UserLogin, TokenResponse
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

def authenticate_user(db: Session, credentials: UserLogin) -> dict:
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
        return {
            "access_token": existing_token.access_token,
            "refresh_token": existing_token.refresh_token,
            "token_type": "bearer"
        }

    access_token = create_token(
        {"sub": user.username, "type": "access"},
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_token(
        {"sub": user.username, "type": "refresh"},
        timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    )

    new_token = Token(
        access_token=access_token,
        refresh_token=refresh_token,
        user_id=user.id
    )

    db.add(new_token)
    db.commit()
    db.refresh(new_token)

    return {
        "access_token": new_token.access_token,
        "refresh_token": new_token.refresh_token,
        "token_type": "bearer"
    }

def invalidate_user(db: Session, token: str) -> Token:
    token = db.query(Token).filter(Token.access_token == token).first()
    if token:
        token.is_valid = False
        db.commit()
        return Token
    else:
        raise HTTPException(status_code=404, detail="Token doesn't exists")
    
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
def verify_token(db: Session, token: str = Depends(oauth2_scheme)) -> bool:
    token_entry = db.query(Token).filter_by(access_token=token, is_valid=True).first()
    return token_entry is not None


def refresh_token(db: Session, token: str = Depends(oauth2_scheme)) -> TokenResponse:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")

        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token payload")

        user = db.query(User).filter_by(username=username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        access_token = create_token(
            data={"sub": username, "type": "access"},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        refresh_token = create_token(
            {"sub": username, "type": "refresh"},
            timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
        )

        new_token = Token(
            access_token=access_token,
            refresh_token=refresh_token,
            user_id=user.id
        )

        db.add(new_token)
        db.commit()
        db.refresh(new_token)

        return TokenResponse(
            access_token=access_token,
            refresh_token=token,
            token_type="bearer"
        )

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
