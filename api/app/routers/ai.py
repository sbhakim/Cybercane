from fastapi import APIRouter

from ..schemas import EmailIn, AIAnalyzeOut
from ..pipeline.classify import classify_email
from ..ai_service.service import analyze_email


router = APIRouter()


@router.post("/analyze", response_model=AIAnalyzeOut)
def analyze(payload: EmailIn) -> AIAnalyzeOut:
    # Phase 1: deterministic pipeline first
    phase1 = classify_email(payload.model_dump())
    # Phase 2: AI analysis with RAG
    result = analyze_email(payload, phase1)
    return result

