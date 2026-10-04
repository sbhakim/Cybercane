"""
External-call privacy boundary.

Every piece of email-derived text sent to an external provider (embeddings,
LLM explanations, LLM baselines, corpus ingestion) must pass through
`sanitize_for_external`. Keeping one entry point makes the boundary auditable:
a grep for provider calls must show each one fed by this module.
"""

from __future__ import annotations

from typing import Optional, Tuple

from .redactor import REDACTOR_VERSION, RedactionReport, redact_v2

__all__ = ["REDACTOR_VERSION", "sanitize_for_external", "sanitize_field", "truncate_for_embedding"]

# Conservative token estimate (no tokenizer dependency): ASCII ~2 chars/token,
# non-ASCII (e.g. CJK) ~1.5 tokens/char. Keeps inputs under the 8,192-token limit.
EMBED_TOKEN_BUDGET = 7000


def truncate_for_embedding(text: str, budget: int = EMBED_TOKEN_BUDGET) -> str:
    """Truncate text so its estimated token count stays within the embedding limit."""
    est = 0.0
    for i, ch in enumerate(text):
        est += 0.5 if ord(ch) < 128 else 1.5
        if est > budget:
            return text[:i]
    return text


def sanitize_field(text: Optional[str]) -> Tuple[str, RedactionReport]:
    """Sanitize a single field (subject, body, or neighbor text)."""
    return redact_v2(text)


def sanitize_for_external(
    subject: Optional[str], body: Optional[str], *, max_chars: int = 8000
) -> Tuple[str, RedactionReport]:
    """
    Build the text representation used for embeddings from sanitized fields.

    The same function is used for corpus ingestion and for queries, so both
    sides of the similarity comparison share one representation.
    """
    red_subject, rep_s = redact_v2(subject)
    red_body, rep_b = redact_v2(body)
    report = RedactionReport(ner_used=rep_s.ner_used or rep_b.ner_used)
    for rep in (rep_s, rep_b):
        for k, v in rep.counts.items():
            report.add(k, v)
    text = f"{red_subject}\n\n{red_body}".strip()[:max_chars]
    return text, report
