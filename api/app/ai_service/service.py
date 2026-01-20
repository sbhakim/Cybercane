"""
Phase 2: Retrieval-Augmented Generation (RAG) Analysis Service

This module implements the semantic analysis layer that extends deterministic
rule-based detection with embedding-based similarity search. The architecture
maintains optional AI dependencies with graceful degradation when external
services are unavailable.

Core Capabilities:
- Text embedding generation using OpenAI or DeepSeek APIs
- Vector similarity search against labeled phishing corpus
- LLM-based explanation generation for classification decisions
- Hybrid verdict computation combining deterministic and semantic signals

Design Philosophy:
The service prioritizes reliability through fallback mechanisms. If embeddings
or LLM calls fail, the system degrades to deterministic analysis without
breaking the detection pipeline.
"""

from __future__ import annotations

import os
import logging
from typing import List, Tuple, Optional

import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

from app.db import engine
from app.schemas import EmailIn, ScanOut, AIAnalyzeOut, NeighborOut, RedactionsOut, OntologyAttack
from app.pipeline.pii import redact

# Neuro-symbolic ontology reasoning
try:
    from app.symbolic.ontology_reasoner import (
        PhishingOntologyReasoner,
        indicators_to_ontology_format,
        create_reasoner
    )
    ONTOLOGY_AVAILABLE = True
except ImportError:
    ONTOLOGY_AVAILABLE = False
    PhishingOntologyReasoner = None

logger = logging.getLogger(__name__)

# ============================================================================
# Global Ontology Reasoner (cached for performance)
# ============================================================================

_ONTOLOGY_REASONER: Optional[PhishingOntologyReasoner] = None


def get_ontology_reasoner() -> Optional[PhishingOntologyReasoner]:
    """
    Get cached ontology reasoner instance.

    Lazy initialization: creates reasoner on first call and caches for reuse.
    This avoids reloading the 164-triple ontology on every request.

    Returns:
        PhishingOntologyReasoner instance or None if unavailable
    """
    global _ONTOLOGY_REASONER

    if not ONTOLOGY_AVAILABLE:
        return None

    if _ONTOLOGY_REASONER is None:
        try:
            _ONTOLOGY_REASONER = create_reasoner()
            logger.info("Ontology reasoner initialized and cached")
        except Exception as e:
            logger.warning(f"Failed to initialize ontology reasoner: {e}")
            return None

    return _ONTOLOGY_REASONER


# ============================================================================
# AI Provider Configuration
# ============================================================================

def _resolve_ai_provider(prefer_deepseek: bool = False) -> tuple[str, str, str | None]:
    """
    Determine which AI provider to use based on available credentials.

    Provider selection follows a preference order:
    1. If prefer_deepseek=True and DeepSeek credentials exist, use DeepSeek
    2. Else if OpenAI credentials exist, use OpenAI
    3. Else if DeepSeek credentials exist, use DeepSeek
    4. Else return empty (no provider available)

    Args:
        prefer_deepseek: Whether to prioritize DeepSeek over OpenAI when both available

    Returns:
        Tuple of (provider_name, api_key, base_url)
        Returns ("", "", None) if no valid provider credentials found
    """
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    openai_base = os.getenv("OPENAI_BASE_URL", "").strip()
    deepseek_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    deepseek_base = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").strip()

    if prefer_deepseek and deepseek_key:
        return "deepseek", deepseek_key, deepseek_base
    if openai_key:
        return "openai", openai_key, openai_base or None
    if deepseek_key:
        return "deepseek", deepseek_key, deepseek_base

    return "", "", None


def _build_ai_client(prefer_deepseek: bool = False) -> tuple["OpenAI", str]:
    """
    Initialize OpenAI-compatible client with configured credentials.

    The client works with both OpenAI and DeepSeek APIs since DeepSeek
    maintains OpenAI compatibility. This allows seamless fallback between
    providers without code changes.

    Args:
        prefer_deepseek: Whether to attempt DeepSeek before OpenAI

    Returns:
        Tuple of (OpenAI client instance, provider name)

    Raises:
        RuntimeError: If openai package unavailable or no credentials configured
    """
    try:
        from openai import OpenAI
    except Exception as e:
        raise RuntimeError(
            "openai package not available. Rebuild the api image after updating requirements.txt"
        ) from e

    provider, api_key, base_url = _resolve_ai_provider(prefer_deepseek)
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set and no DEEPSEEK_API_KEY available")

    # Use custom base_url if provided, otherwise default to provider's endpoint
    if base_url:
        return OpenAI(api_key=api_key, base_url=base_url), provider
    return OpenAI(api_key=api_key), provider


def _combine_subject_body(subject: str | None, body: str | None) -> str:
    """
    Concatenate email subject and body for embedding generation.

    Applies a size cap to prevent oversized payloads that could cause
    API timeouts or exceed token limits. The 8000 character limit provides
    enough context while staying well under typical API constraints.

    Args:
        subject: Email subject line (may be None)
        body: Email body content (may be None)

    Returns:
        Combined text string, capped at 8000 characters
    """
    text_value = f"{subject or ''}\n\n{body or ''}".strip()
    return text_value[:8000]


# ============================================================================
# Embedding and Vector Retrieval
# ============================================================================

def _embed_text(text_value: str, model: str = "text-embedding-3-small") -> List[float]:
    """
    Generate embedding vector for given text using configured AI provider.

    Uses OpenAI's text-embedding-3-small by default (1536 dimensions).
    For DeepSeek, the model name comes from DEEPSEEK_EMBEDDING_MODEL env var.

    Implements automatic fallback: if OpenAI fails, attempts DeepSeek if available.
    This ensures embedding generation succeeds when either provider is operational.

    Args:
        text_value: Text to embed
        model: Embedding model name (OpenAI format)

    Returns:
        1536-dimensional float vector

    Raises:
        RuntimeError: If no valid credentials or both providers fail
    """
    client, provider = _build_ai_client()
    embed_model = model

    # DeepSeek requires explicit model specification via environment variable
    if provider == "deepseek":
        embed_model = os.getenv("DEEPSEEK_EMBEDDING_MODEL", "").strip()
        if not embed_model:
            raise RuntimeError("DEEPSEEK_EMBEDDING_MODEL is not set for DeepSeek embeddings")

    try:
        resp = client.embeddings.create(model=embed_model, input=[text_value])
        return resp.data[0].embedding
    except Exception as exc:
        # Automatic fallback to DeepSeek if we were using OpenAI
        if provider != "deepseek":
            try:
                client, provider = _build_ai_client(prefer_deepseek=True)
            except Exception:
                raise

            embed_model = os.getenv("DEEPSEEK_EMBEDDING_MODEL", "").strip()
            if provider == "deepseek" and not embed_model:
                raise RuntimeError("DEEPSEEK_EMBEDDING_MODEL is not set for DeepSeek embeddings") from exc

            resp = client.embeddings.create(model=embed_model or model, input=[text_value])
            return resp.data[0].embedding
        raise exc


def _nearest_neighbors(
    vec: List[float],
    limit: int = 8,
    *,
    include_benign: bool = False
) -> List[NeighborOut]:
    """
    Retrieve top-k most similar emails using pgvector cosine similarity.

    Queries the messages table using pgvector's <-> operator for cosine distance.
    By default, restricts to phishing-labeled examples (label=1) to create a
    pure phishing corpus for similarity matching.

    Implementation Note:
    pgvector computes cosine distance (0=identical, 2=opposite), so we convert
    to similarity (0-1 range) using: similarity = 1 - distance

    Args:
        vec: 1536-dim query vector
        limit: Maximum number of neighbors to return
        include_benign: Whether to include benign emails (label=0) in results

    Returns:
        List of NeighborOut objects sorted by descending similarity

    Database Requirements:
        - PostgreSQL with pgvector extension
        - HNSW index on doc_emb column for efficient search
    """
    # Build WHERE clause to filter by label if needed
    where_clause = "WHERE doc_emb IS NOT NULL"
    if not include_benign:
        where_clause += " AND label = 1"

    # Raw SQL for pgvector operations (SQLAlchemy ORM doesn't support vector ops well)
    stmt = sa.text(
        f"""
        SELECT id,
               label,
               subject,
               body,
               redacted_body,
               1 - (doc_emb <-> :q) AS cosine_similarity
        FROM messages
        {where_clause}
        ORDER BY doc_emb <-> :q
        LIMIT :lim
        """
    ).bindparams(sa.bindparam("q", type_=Vector(1536)))

    rows: List[Tuple[int, int | None, str | None, str | None, str | None, float]] = []
    with engine.connect() as conn:
        result = conn.execute(stmt, {"q": vec, "lim": int(limit)})
        rows = list(result.fetchall())

    # Convert database rows to Pydantic models
    neighbors: List[NeighborOut] = []
    for _id, label, subject, body, redacted_body, sim in rows:
        # Prefer redacted_body if available to avoid exposing PII
        body_value = redacted_body or body
        neighbors.append(
            NeighborOut(
                id=int(_id),
                label=(int(label) if label is not None else None),
                subject=subject,
                body=body_value,
                similarity=float(sim),
            )
        )
    return neighbors


# ============================================================================
# LLM-Based Explanation Generation
# ============================================================================

def _summarize_reasons_with_llm(
    *,
    subject: str,
    body: str,
    phase1: ScanOut,
    neighbors: List[NeighborOut],
    model: str = "gpt-4.1-mini",
) -> List[str]:
    """
    Generate human-readable explanation using LLM with retrieval context.

    Constructs a prompt that includes:
    - Email content (subject + body)
    - Phase 1 deterministic indicators (auth flags, DNS results)
    - Neighbor similarity statistics
    - Top-k similar phishing examples

    The LLM synthesizes these signals into 3-5 concise bullet points explaining
    why the email may or may not be phishing. Each bullet is tagged with category
    markers like [AUTH], [SIMILARITY], [URGENCY] for structured output.

    Fallback Strategy:
    If LLM call fails (rate limit, timeout, credentials), returns Phase 1 reasons
    with a fallback message. This ensures the user always gets an explanation.

    Args:
        subject: Email subject line
        body: Email body (should be redacted to avoid PII exposure)
        phase1: Deterministic analysis results
        neighbors: Retrieved similar emails with similarity scores
        model: LLM model name (OpenAI format)

    Returns:
        List of 3-5 explanation strings
    """
    try:
        client, provider = _build_ai_client()
    except Exception:
        # Fallback if client cannot be initialized
        return [
            "AI client unavailable; showing deterministic reasons only.",
            *[r for r in phase1.reasons][:3],
        ]

    # Build concise context from top neighbors
    # All neighbors are phishing-labeled due to retrieval filter
    neighbor_lines = []
    for n in neighbors[:8]:
        neighbor_lines.append(
            f"id={n.id} label=phish sim={n.similarity:.2f} subj={(n.subject or '')[:60]}"
        )

    # Compute aggregate similarity metrics for prompt
    sims = sorted([float(n.similarity) for n in neighbors], reverse=True)
    top_sim = sims[0] if sims else 0.0
    avg_top3 = (sum(sims[:3]) / max(1, min(3, len(sims)))) if sims else 0.0
    avg_all = (sum(sims) / len(sims)) if sims else 0.0

    # Extract key deterministic indicators for LLM context
    inds = phase1.indicators or {}
    def _yn(v: object) -> str:
        return "yes" if bool(v) else "no"

    sender_domain = inds.get("sender_domain") or ""

    # Build structured evidence block from Phase 1 detected violations
    detected_evidence = []
    if phase1.reasons:
        detected_evidence.append("DETECTED VIOLATIONS (cite these exactly):")
        for idx, reason in enumerate(phase1.reasons, 1):
            detected_evidence.append(f"  {idx}. {reason}")
    else:
        detected_evidence.append("DETECTED VIOLATIONS: None")

    # Add technical auth/DNS details as supplementary evidence
    detected_evidence.extend([
        "",
        "TECHNICAL INDICATORS:",
        f"  - Sender domain: {sender_domain}",
        f"  - MX record present: {_yn(inds.get('has_mx'))}",
        f"  - SPF record present: {_yn(inds.get('spf_present'))}",
        f"  - DMARC record present: {_yn(inds.get('dmarc_present'))}",
        f"  - DMARC policy: {inds.get('dmarc_policy', 'none')}",
    ])

    evidence_block = "\n".join(detected_evidence)

    # Construct prompt that ENFORCES explicit evidence citation
    prompt = (
        "System: You are a security assistant analyzing phishing risk. You MUST base ALL explanations on evidence provided below.\n\n"
        "CRITICAL RULES:\n"
        "1. For [AUTH] tags: CITE specific DNS/SPF/DMARC failures from TECHNICAL INDICATORS\n"
        "2. For [URL] tags: CITE specific URL patterns from DETECTED VIOLATIONS\n"
        "3. For [URGENCY] tags: CITE specific urgency keywords from DETECTED VIOLATIONS\n"
        "4. For [CONTENT] tags: CITE specific credential/PHI requests from DETECTED VIOLATIONS\n"
        "5. For [SIMILARITY] tags: Reference neighbor similarity stats below\n"
        "6. DO NOT generate explanations without citing provided evidence\n"
        "7. If no evidence exists for a category, DO NOT use that tag\n\n"
        "=== EMAIL TO ANALYZE ===\n"
        f"Subject: {subject[:200]}\n"
        f"Body (redacted): {body[:800]}\n\n"
        "=== EVIDENCE FROM PHASE 1 ANALYSIS ===\n"
        + evidence_block + "\n\n"
        "=== RETRIEVAL CONTEXT ===\n"
        f"Neighbor Stats (phish-only corpus): top_sim={top_sim:.2f}, avg_top3={avg_top3:.2f}, avg_all={avg_all:.2f}\n"
        "Top Similar Emails:\n- " + "\n- ".join(neighbor_lines) + "\n\n"
        "Task: Write 3–5 concise bullets (under 18 words each). Start each with a bracketed tag. "
        "CITE SPECIFIC evidence from above (e.g., '[AUTH] No SPF record for domain X').\n\n"
        "Respond as bullet points only, no preface."
    )

    try:
        # Provider-specific API call formats
        if provider == "deepseek":
            model_name = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
            resp = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,  # Low temperature for consistent, factual output
                max_tokens=500,
            )
            text = resp.choices[0].message.content or ""
        else:
            # OpenAI Responses API format
            resp = client.responses.create(
                model=model,
                input=prompt,
                temperature=0.2,
            )
            text = getattr(resp, "output_text", None)
            if not text:
                text = str(resp)  # Best-effort extraction
    except Exception:
        # Automatic fallback to DeepSeek if OpenAI fails
        if provider != "deepseek":
            try:
                client, provider = _build_ai_client(prefer_deepseek=True)
                model_name = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
                resp = client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.2,
                    max_tokens=500,
                )
                text = resp.choices[0].message.content or ""
            except Exception:
                return [
                    "AI API call failed; showing deterministic reasons only.",
                    *[r for r in phase1.reasons][:3],
                ]
        else:
            return [
                "AI API call failed; showing deterministic reasons only.",
                *[r for r in phase1.reasons][:3],
            ]

    # Parse LLM output into individual bullet points
    lines = [ln.strip(" -\t") for ln in text.splitlines() if ln.strip()]
    reasons = [ln for ln in lines if ln][:5]  # Cap at 5 bullets

    if not reasons:
        reasons = [text.strip()[:200]]  # Fallback if parsing fails

    return reasons


# ============================================================================
# Verdict and Scoring Logic
# ============================================================================

def _decide_ai_verdict(phase1: ScanOut, phish_neighbors: List[NeighborOut]) -> str:
    """
    Compute final verdict by combining deterministic and semantic signals.

    Verdict Logic:
    1. If Phase 1 classified as phishing, immediately return "phishing"
       (high-confidence deterministic signals override semantic analysis)

    2. Else, check similarity to known phishing:
       - top_sim ≥ 0.70: Strong match to known phishing → "phishing"
       - top_sim ≥ 0.55 OR avg_top3 ≥ 0.52: Moderate match → "needs_review"

    3. If Phase 1 verdict was "needs_review" and avg_top3 ≥ 0.68:
       Escalate to "phishing" (borderline deterministic + strong semantic signal)

    4. Otherwise, return Phase 1 verdict unchanged

    Threshold Tuning:
    Current thresholds (0.70/0.68/0.55/0.52) were determined through validation
    set optimization. Lower thresholds improve recall while maintaining precision
    through Phase 1 filtering.

    Args:
        phase1: Deterministic analysis results
        phish_neighbors: Retrieved phishing-labeled neighbors with similarity scores

    Returns:
        Final verdict: "phishing", "needs_review", or "benign"
    """
    # Pass-through for high-confidence deterministic phishing
    if phase1.verdict == "phishing":
        return "phishing"

    # Compute similarity statistics from retrieved neighbors
    top_sim = max((n.similarity for n in phish_neighbors), default=0.0)
    avg_top3 = sum(sorted((n.similarity for n in phish_neighbors), reverse=True)[:3]) / max(
        1, min(3, len(phish_neighbors))
    ) if phish_neighbors else 0.0

    # Apply tuned thresholds for semantic-based classification
    if top_sim >= 0.70 or (phase1.verdict == "needs_review" and avg_top3 >= 0.68):
        return "phishing"
    if top_sim >= 0.55 or avg_top3 >= 0.52:
        return "needs_review"

    return phase1.verdict


def _compute_ai_score(phase1: ScanOut, neighbors: List[NeighborOut]) -> int:
    """
    Generate 0-10 risk score combining semantic and deterministic signals.

    Scoring Algorithm:
    - Base signal: Weighted combination of top similarity (65%) and avg top-3 (35%)
    - Deterministic boost: Add influence from Phase 1 verdict
      * "phishing" → 1.0 boost
      * "needs_review" → 0.6 boost
      * "benign" → 0.0 boost
    - Combined: max(base, 70% base + 30% deterministic)
    - Scale to 0-10 range

    Design Rationale:
    The score emphasizes semantic similarity (which captures subtle patterns)
    while using deterministic signals as a secondary indicator. The max()
    operation ensures strong semantic signals aren't diluted by weak
    deterministic signals.

    Args:
        phase1: Deterministic analysis results
        neighbors: All retrieved neighbors (phishing + benign if included)

    Returns:
        Integer score 0-10 where higher indicates greater phishing likelihood
    """
    phish_neighbors = [n for n in neighbors if n.label == 1]

    # Extract similarity metrics
    top_overall = max((n.similarity for n in neighbors), default=0.0)
    top_phish = max((n.similarity for n in phish_neighbors), default=0.0)
    avg_top3_phish = (
        sum(sorted((n.similarity for n in phish_neighbors), reverse=True)[:3])
        / max(1, min(3, len(phish_neighbors)))
        if phish_neighbors
        else 0.0
    )

    # Compute neighbor-based signal (prefer phishing-labeled neighbors)
    if phish_neighbors:
        neighbor_signal = 0.65 * top_phish + 0.35 * avg_top3_phish
    else:
        neighbor_signal = 0.5 * top_overall  # Fallback if no phishing neighbors

    # Map Phase 1 verdict to numeric signal
    phase1_signal = 1.0 if phase1.verdict == "phishing" else (
        0.6 if phase1.verdict == "needs_review" else 0.0
    )

    # Combine signals with max to prevent strong semantic signal dilution
    combined = max(neighbor_signal, 0.7 * neighbor_signal + 0.3 * phase1_signal)
    combined = max(0.0, min(1.0, combined))  # Clamp to [0, 1]

    return int(round(combined * 10))


# ============================================================================
# Public API
# ============================================================================

def analyze_email(payload: EmailIn, phase1: ScanOut, *, neighbors_k: int = 8) -> AIAnalyzeOut:
    """
    Perform complete RAG-based phishing analysis.

    Pipeline:
    0. [NEW] Ontology-based semantic inference from Phase 1 indicators
    1. Combine subject + body and generate embedding vector
    2. Retrieve k nearest neighbors from phishing corpus via pgvector
    3. Compute AI verdict using similarity-based thresholds
    4. Generate LLM explanation synthesizing deterministic + semantic signals
    5. Calculate 0-10 risk score
    6. Redact PII from neighbor examples before returning

    Graceful Degradation:
    If embeddings fail (API down, credentials missing), returns minimal output
    using only Phase 1 deterministic analysis. This ensures the pipeline never
    breaks due to external service failures.

    Args:
        payload: Input email with subject and body
        phase1: Completed Phase 1 deterministic analysis
        neighbors_k: Number of neighbors to retrieve (default: 8)

    Returns:
        AIAnalyzeOut containing verdict, score, explanations, and neighbor context
    """
    # ========================================================================
    # STEP 0: Ontology-based Semantic Inference (NEURO-SYMBOLIC)
    # ========================================================================
    ontology_attacks: Optional[List[OntologyAttack]] = None
    ontology_explanation: Optional[List[str]] = None

    reasoner = get_ontology_reasoner()
    if reasoner and phase1.indicators:
        try:
            # Convert Phase 1 indicators to ontology format
            ontology_indicators = indicators_to_ontology_format(phase1.indicators)

            # Infer attack types using description logic reasoning
            inferred_attacks = reasoner.infer_attack_types(ontology_indicators, min_confidence=0.3)

            if inferred_attacks:
                # Convert to schema format
                ontology_attacks = [
                    OntologyAttack(attack_type=name, confidence=conf)
                    for name, conf in inferred_attacks
                ]

                # Generate explanation chain for top attack
                top_attack = inferred_attacks[0][0]
                ontology_explanation = reasoner.get_explanation_chain(
                    ontology_indicators,
                    top_attack
                )

                logger.info(f"Ontology inferred {len(ontology_attacks)} attack types, "
                           f"top: {top_attack} ({inferred_attacks[0][1]*100:.1f}%)")
        except Exception as e:
            logger.warning(f"Ontology inference failed: {e}")
            # Graceful degradation: continue without ontology

    # ========================================================================
    # STEP 1: Neural Embedding & Retrieval (continues as before)
    # ========================================================================
    doc_text = _combine_subject_body(payload.subject, payload.body)

    try:
        vec = _embed_text(doc_text)
    except Exception:
        # Graceful degradation: return deterministic-only analysis
        neighbors: List[NeighborOut] = []
        phish_neighbors: List[NeighborOut] = []
        ai_reasons = [
            "Embeddings unavailable; relying on deterministic analysis only.",
            *[r for r in phase1.reasons][:3],
        ]
        ai_verdict = phase1.verdict
        ai_label = 1 if ai_verdict == "phishing" else 0

        inds = phase1.indicators or {}
        dmarc_policy = str(inds.get("dmarc_policy", "none"))
        conclusion = (
            f"Conclusion: **PHISH** — weak auth or risky patterns (DMARC: {dmarc_policy})"
            if ai_label == 1
            else f"Conclusion: **LEGIT** — insufficient phish signals and auth not risky (DMARC: {dmarc_policy})"
        )
        ai_reasons.append(conclusion)

        return AIAnalyzeOut(
            phase1=phase1,
            neighbors=neighbors,
            phish_neighbors=phish_neighbors,
            ai_verdict=ai_verdict,  # type: ignore[arg-type]
            ai_label=ai_label,
            ai_score=phase1.score,
            ai_reasons=ai_reasons,
            ontology_attacks=ontology_attacks,  # NEW: Ontology inference
            ontology_explanation=ontology_explanation,  # NEW: Reasoning chain
        )

    # Retrieve similar emails from vector database
    neighbors = _nearest_neighbors(vec, limit=neighbors_k)

    # Redact PII from neighbor examples to prevent data exposure
    for neighbor in neighbors:
        redacted_subject, subject_counts = redact(neighbor.subject or "")
        redacted_body, body_counts = redact(neighbor.body or "")

        # Merge redaction counts from subject and body
        merged_keys = set(subject_counts.keys()) | set(body_counts.keys())
        merged_counts: dict[str, int] = {
            k: int(subject_counts.get(k, 0)) + int(body_counts.get(k, 0))
            for k in merged_keys
        }

        neighbor.subject = redacted_subject
        neighbor.body = redacted_body
        neighbor.redactions = RedactionsOut(types=merged_counts, count=sum(merged_counts.values()))

    phish_neighbors = [n for n in neighbors if n.label == 1]

    # Compute verdict without exposing it to LLM (prevents label leakage)
    ai_verdict = _decide_ai_verdict(phase1, phish_neighbors)
    ai_label = 1 if ai_verdict == "phishing" else 0

    # Generate human-readable explanations using LLM
    ai_reasons = _summarize_reasons_with_llm(
        subject=payload.subject,
        body=phase1.redacted_body or payload.body,
        phase1=phase1,
        neighbors=neighbors,
    )

    # Append conclusion line summarizing final stance
    inds = phase1.indicators or {}
    dmarc_policy = str(inds.get("dmarc_policy", "none"))

    if ai_label == 1:
        why = "matches known phish and weak auth (DMARC: " + dmarc_policy + ")"
        conclusion = f"Conclusion: **PHISH** — {why}"
    else:
        why = "no strong phish match and auth not clearly risky (DMARC: " + dmarc_policy + ")"
        conclusion = f"Conclusion: **LEGIT** — {why}"

    if conclusion not in ai_reasons:
        ai_reasons.append(conclusion)

    ai_score = _compute_ai_score(phase1, neighbors)

    return AIAnalyzeOut(
        phase1=phase1,
        neighbors=neighbors,
        phish_neighbors=phish_neighbors,
        ai_verdict=ai_verdict,  # type: ignore[arg-type]
        ai_label=ai_label,
        ai_score=ai_score,
        ai_reasons=ai_reasons,
        ontology_attacks=ontology_attacks,  # NEW: Ontology inference
        ontology_explanation=ontology_explanation,  # NEW: Reasoning chain
    )
