from __future__ import annotations

from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Use a file-based SQLite DB in the project root. Adjust path as needed.
# For absolute path (recommended in some environments), you can use for example:
# SQLALCHEMY_DATABASE_URL = "sqlite:////workspace/app.db"
SQLALCHEMY_DATABASE_URL: str = "sqlite:///./app.db"

# SQLite + SQLAlchemy (sync) needs this flag for multi-threaded FastAPI use
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    class_=Session,
)

Base = declarative_base()


def create_all_tables() -> None:
    """Create all tables defined on the shared Base metadata.

    Import models before calling to ensure mappers are configured.
    """
    # Import models to register them with Base.metadata
    from app import models  # noqa: F401  (import-only side effect)

    Base.metadata.create_all(bind=engine)


def dispose_engine() -> None:
    """Dispose of the engine and close all underlying connections."""
    engine.dispose()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session and ensures it is closed.

    Always closes the session in a finally block, so connections are returned
    to the pool even on exceptions.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        # Ensures file descriptors and connections are released deterministically
        db.close()