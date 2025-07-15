from fastapi import FastAPI
from app.auth.routes import router as auth_router
from app.models import Base
from app.db import engine

app = FastAPI()

Base.metadata.create_all(bind=engine)

app.include_router(auth_router)
