import os
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@db:5432/app")

# pool_pre_ping avoids stale connections when the DB is restarted.
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

def db_health() -> bool:
    # Simple connectivity check for /health.
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
