from fastapi import FastAPI, Depends  # type: ignore
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, ForeignKey  # type: ignore
from sqlalchemy.orm import sessionmaker, declarative_base, Session  # type: ignore
import datetime

# Database URL
DATABASE_URL = "postgresql://postgres:yourpassword@localhost/phishing_db"

# SQLAlchemy setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# FastAPI app
app = FastAPI()

# Dependency to get DB session


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
