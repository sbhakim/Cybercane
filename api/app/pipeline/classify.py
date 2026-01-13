"""
Phase 1: Deterministic orchestration.

This module wires the redaction step to the deterministic scorer and returns
a stable, structured response for the API layer. It enforces the privacy-first
ordering: redact before any downstream processing.
"""

from typing import Any, Dict

from ..schemas import ScanOut, RedactionsOut
from .pii import redact
from .deterministic import score_email


# ============================================================================
# Public API
# ============================================================================

def classify_email(payload: Dict[str, Any]) -> ScanOut:
    """
    Orchestrate normalization -> redaction -> deterministic scoring.

    Expects keys: sender, receiver, subject, body, url (0/1)
    """
    sender = payload.get("sender", "")
    subject = payload.get("subject", "")
    body = payload.get("body", "")
    url_flag = int(payload.get("url", 0))

    # Redact before further processing/logging to keep PII out of downstream steps.
    redacted_body, counts = redact(body)

    # Deterministic scoring uses redacted content; DNS checks can be toggled.
    decision = score_email(
        sender=sender,
        subject=subject,
        body=redacted_body,
        url_flag=url_flag,
        allowed_brand_domains=[],
        rule_weights=None,
        enable_dns_checks=True,
    )

    return ScanOut(
        verdict=decision.verdict,
        score=decision.score,
        reasons=decision.reasons,
        indicators=decision.indicators,
        redactions=RedactionsOut(types=counts, count=sum(counts.values())),
        redacted_body=redacted_body,
    )
