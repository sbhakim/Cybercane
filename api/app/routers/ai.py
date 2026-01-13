from fastapi import APIRouter

from ..schemas import EmailIn, AIAnalyzeOut
from ..pipeline.classify import classify_email
from ..ai_service.service import analyze_email


router = APIRouter()


@router.post("/analyze", response_model=AIAnalyzeOut)
def analyze(payload: EmailIn) -> AIAnalyzeOut:
    """
    Phase 1 + Phase 2: full neuro-symbolic analysis.

    Complete phishing detection with deterministic rules + RAG semantic analysis.
    Requires OPENAI_API_KEY environment variable.

    Pipeline:
    1. **Phase 1 (Deterministic):** Symbolic rules and DNS validation
    2. **PII Redaction:** Remove sensitive info before external calls
    3. **Embedding:** Convert to 1536-dim vector (text-embedding-3-small)
    4. **Retrieval:** Find k=8 nearest phishing examples (pgvector HNSW)
    5. **LLM Reasoning:** Generate tagged explanations (GPT-4o-mini)

    Returns (extends Phase 1):
    - `phase1`: Complete deterministic analysis results
    - `neighbors`: Top-8 similar emails with similarity scores
    - `phish_neighbors`: Subset labeled as phishing
    - `ai_verdict`: RAG-enhanced verdict (benign | needs_review | phishing)
    - `ai_label`: Binary classification (0=benign, 1=phishing)
    - `ai_score`: 0-10 combined score (symbolic + semantic)
    - `ai_reasons`: Multi-tagged explanations ([URL], [AUTH], [SIMILARITY], etc.)

    Performance:
    - Latency: ~487ms (median, includes API calls)
    - Precision: 98.9% (k=8, tuned thresholds)
    - Recall: 17.8% (conservative, optimized for low FPR)
    - FPR: 0.16% (1 false alarm per 615 emails)

    Privacy:
    - All PII redacted before OpenAI API calls
    - Only masked content sent to external services
    - HIPAA-compatible architectural boundaries

    Cost:
    - Embedding: ~$0.0004/email
    - LLM reasoning: ~$0.001/email (if needs_review)
    - Total: ~$0.002/email average

    Example response:
    ```json
    {
      "ai_verdict": "phishing",
      "ai_score": 8,
      "ai_reasons": [
        "[AUTH] Missing DMARC record increases spoofing risk",
        "[SIMILARITY] High similarity (0.87) to known phishing corpus",
        "[URL] Shortened URL detected (bit.ly)"
      ]
    }
    ```
    """
    # Phase 1: deterministic pipeline first
    phase1 = classify_email(payload.model_dump())
    # Phase 2: AI analysis with RAG
    result = analyze_email(payload, phase1)
    return result
