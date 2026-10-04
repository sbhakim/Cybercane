from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, EmailStr

# ============================================================================
# Request/Response Schemas
# ============================================================================

class PingOut(BaseModel):
    id: int
    msg: str


class EmailIn(BaseModel):
    """
    Minimal email payload for the Scan Lab and backend pipeline.

    Fields:
    - sender/receiver: email addresses
    - subject/body: message fields
    - url: 1 if email contains at least one link, else 0 (dataset semantics)
    """

    sender: str
    receiver: Optional[str] = None
    subject: str
    body: str
    url: Optional[int] = 0


class RedactionsOut(BaseModel):
    """
    Summary of PII redactions performed.

    Raw PII is never returned.
    """

    types: Dict[str, int]
    count: int


class ScanOut(BaseModel):
    """
    Output of deterministic classifier pipeline.

    Fields:
    - verdict: benign | needs_review | phishing
    - reasons: human-readable explanations for UI transparency
    - indicators: key boolean/numeric indicators used in decisioning
    """

    verdict: Literal["benign", "needs_review", "phishing"]
    score: int
    reasons: List[str]
    indicators: Dict[str, Any]
    redactions: RedactionsOut
    redacted_body: str


class NeighborOut(BaseModel):
    """Nearest-neighbor metadata returned by RAG retrieval."""
    id: int
    label: Optional[int] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    similarity: float
    redactions: Optional[RedactionsOut] = None


class OntologyAttack(BaseModel):
    """
    Attack class asserted by the ontology: every premise of its defining
    axiom holds (confidence is always 1.0), or it is a superclass of one.
    """
    attack_type: str
    confidence: float
    inherited: bool = False


class OntologySuggestion(BaseModel):
    """Partial rule match; NOT asserted. coverage = satisfied/required premises."""
    attack_type: str
    coverage: float
    missing: List[str]


class AIAnalyzeOut(BaseModel):
    """Phase 2 output including AI verdict and supporting context."""
    phase1: ScanOut
    neighbors: List[NeighborOut]
    phish_neighbors: List[NeighborOut]
    ai_verdict: Literal["benign", "needs_review", "phishing"]
    ai_label: Literal[0, 1]
    ai_score: int
    ai_reasons: List[str]

    # Continuous risk in [0, 1] (ranking score, not a probability), the rule that
    # produced ai_verdict ("calibrated" or "legacy"), and whether any external
    # step failed so the result fell back to deterministic analysis.
    ai_risk: Optional[float] = None
    decision_rule: Optional[str] = None
    degraded: bool = False

    # Neuro-symbolic ontology reasoning (NEW)
    ontology_attacks: Optional[List[OntologyAttack]] = None
    ontology_suggestions: Optional[List[OntologySuggestion]] = None
    ontology_explanation: Optional[List[str]] = None
