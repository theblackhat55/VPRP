"""
Database connection and session management.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://vprp_user:changeme@postgres:5432/vprp"
)


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db():
    """Yield a database session, ensuring cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_session():
    """Return a new database session (for non-generator use)."""
    return SessionLocal()
