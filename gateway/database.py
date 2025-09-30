"""Database configuration and session management."""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

try:
    DATABASE_URL = os.environ["DATABASE_URL"]
except KeyError as error:
    raise RuntimeError("DATABASE_URL environment variable must be set") from error

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency for FastAPI to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
