from fastapi import APIRouter
from ..db import db_health

router = APIRouter()


@router.get("")
def health():
    """Return API status and DB connectivity flag."""
    return {"status": "ok", "db": db_health()}
