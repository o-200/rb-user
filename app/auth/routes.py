from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.schemas import UserCreate, UserLogin, Token
from app.auth.service import register_user, authenticate_user, invalidate_user, verify_token
from app.auth.utils import get_token
from app.db import get_db

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(get_db)):
    register_user(db, user)
    return authenticate_user(db, UserLogin(username=user.username, password=user.password))

@router.post("/login", response_model=Token)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    return authenticate_user(db, credentials)

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(token: str = Depends(get_token), db: Session = Depends(get_db)):
    invalidate_user(db, token)
    return

@router.get("/verify", status_code=status.HTTP_200_OK)
def verify(token: str = Depends(get_token), db: Session = Depends(get_db)):
    return verify_token(db, token)
