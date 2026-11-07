from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings

DATABASE_URL = get_settings().database_url
IS_SQLITE = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    **({} if IS_SQLITE else {"pool_size": 10, "max_overflow": 20}),
)

if IS_SQLITE:

    @event.listens_for(engine, "connect")
    def _sqlite_concurrency(dbapi_connection, _record) -> None:
        # WAL lets readers and one writer work concurrently; busy_timeout makes a writer wait
        # for a lock instead of failing with "database is locked" under load.
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=15000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
