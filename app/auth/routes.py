from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.schemas import UserCreate, UserLogin, Token
from app.auth.service import register_user, authenticate_user
from app.db import get_db

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(get_db)):
    register_user(db, user)
    return authenticate_user(db, UserLogin(username=user.username, password=user.password))

@router.post("/login", response_model=Token)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    return authenticate_user(db, credentials)
