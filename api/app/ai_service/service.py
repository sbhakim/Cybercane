"""
Phase-2 AI analysis: embed, retrieve nearest neighbors, and summarize reasons.
This module keeps AI calls optional and provides safe fallbacks.
"""

from __future__ import annotations

import os
from typing import List, Tuple

import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

from app.db import engine
from app.schemas import EmailIn, ScanOut, AIAnalyzeOut, NeighborOut, RedactionsOut
from app.pipeline.pii import redact


def _resolve_ai_provider(prefer_deepseek: bool = False) -> tuple[str, str, str | None]:
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
    try:
        from openai import OpenAI
    except Exception as e:
        raise RuntimeError(
            "openai package not available. Rebuild the api image after updating requirements.txt"
        ) from e

    provider, api_key, base_url = _resolve_ai_provider(prefer_deepseek)
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set and no DEEPSEEK_API_KEY available")

    if base_url:
        return OpenAI(api_key=api_key, base_url=base_url), provider
    return OpenAI(api_key=api_key), provider


def _combine_subject_body(subject: str | None, body: str | None) -> str:
    text_value = f"{subject or ''}\n\n{body or ''}".strip()
    # keep a reasonable cap to avoid oversized payloads
    return text_value[:8000]

# ---- Embedding + retrieval helpers ----


def _embed_text(text_value: str, model: str = "text-embedding-3-small") -> List[float]:
    """
    Create a single embedding vector for the given text using OpenAI embeddings API.
    Returns a 1536-dim vector (per model spec) or raises RuntimeError if misconfigured.
    """
    client, provider = _build_ai_client()
    embed_model = model
    if provider == "deepseek":
        embed_model = os.getenv("DEEPSEEK_EMBEDDING_MODEL", "").strip()
        if not embed_model:
            raise RuntimeError("DEEPSEEK_EMBEDDING_MODEL is not set for DeepSeek embeddings")

    try:
        resp = client.embeddings.create(model=embed_model, input=[text_value])
        return resp.data[0].embedding
    except Exception as exc:
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


def _nearest_neighbors(vec: List[float], limit: int = 8) -> List[NeighborOut]:
    """
    Return top-k neighbors by cosine similarity against messages.doc_emb.
    Uses pgvector with cosine distance operator (<->) and converts to similarity.
    """
    stmt = sa.text(
        """
        SELECT id,
               label,
               subject,
               body,
               redacted_body,
               1 - (doc_emb <-> :q) AS cosine_similarity
        FROM messages
        WHERE doc_emb IS NOT NULL AND label = 1
        ORDER BY doc_emb <-> :q
        LIMIT :lim
        """
    ).bindparams(
        sa.bindparam("q", type_=Vector(1536)),
    )

    rows: List[Tuple[int, int | None, str | None, str | None, str | None, float]] = []
    with engine.connect() as conn:
        # psycopg binds arrays via pgvector; ensure limit is int
        result = conn.execute(stmt, {"q": vec, "lim": int(limit)})
        rows = list(result.fetchall())

    neighbors: List[NeighborOut] = []
    for _id, label, subject, body, redacted_body, sim in rows:
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


# ---- LLM summarization helpers ----

def _summarize_reasons_with_llm(
    *,
    subject: str,
    body: str,
    phase1: ScanOut,
    neighbors: List[NeighborOut],
    model: str = "gpt-4.1-mini",
) -> List[str]:
    """
    Use OpenAI Responses API to produce 3-5 concise reasons for/against phishing,
    grounded in Phase-1 flags and nearest neighbors.
    If the API is unavailable, fall back to a simple heuristic message.
    """
    try:
        client, provider = _build_ai_client()
    except Exception:
        # Fallback if client missing or misconfigured
        return [
            "AI client unavailable; showing deterministic reasons only.",
            *[r for r in phase1.reasons][:3],
        ]

    # Build concise neighbor context (all neighbors are labeled phishing due to retrieval filter)
    neighbor_lines = []
    for n in neighbors[:8]:
        neighbor_lines.append(
            f"id={n.id} label=phish sim={n.similarity:.2f} subj={(n.subject or '')[:60]}"
        )

    # Aggregate similarity stats for stronger guidance
    sims = sorted([float(n.similarity) for n in neighbors], reverse=True)
    top_sim = sims[0] if sims else 0.0
    avg_top3 = (sum(sims[:3]) / max(1, min(3, len(sims)))) if sims else 0.0
    avg_all = (sum(sims) / len(sims)) if sims else 0.0

    # Summarize key deterministic indicators for the LLM
    inds = phase1.indicators or {}
    def _yn(v: object) -> str:
        return "yes" if bool(v) else "no"

    sender_domain = inds.get("sender_domain") or ""
    # Provide only deterministic indicators (no previous verdict/score)
    phase1_summary = (
        f"auth(has_mx={_yn(inds.get('has_mx'))}, spf_present={_yn(inds.get('spf_present'))}, "
        f"dmarc_present={_yn(inds.get('dmarc_present'))}, dmarc_policy={inds.get('dmarc_policy', 'none')}) "
        f"sender_domain={sender_domain}"
    )

    prompt = (
        "System: You are a security assistant. All retrieved neighbors are labeled phishing (label=1). "
        "Use them as risk exemplars for retrieval-augmented reasoning. Weigh deterministic auth flags and neighbor similarity.\n\n"
        "Task: Write 3–5 concise bullets explaining risk. Start each bullet with a tag in brackets "
        "such as [URL], [AUTH], [URGENCY], [SIMILARITY], [CONTENT]. Keep each under 18 words. Do not mention any prior verdict or percentage scores.\n\n"
        + "Email Subject:\n" + subject[:200]
        + "\nEmail Body (redacted):\n" + body[:800]
        + "\n\nDeterministic Summary:\n" + phase1_summary
        + "\n\nNeighbor Stats (phish-only): top_sim=" + f"{top_sim:.2f}" +
          ", avg_top3=" + f"{avg_top3:.2f}" + ", avg_all=" + f"{avg_all:.2f}" +
        "\nNeighbors (doc_emb cosine similarity):\n- " + "\n- ".join(neighbor_lines) +
        "\n\nRespond as bullet points only, no preface."
    )

    try:
        if provider == "deepseek":
            model_name = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
            resp = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=500,
            )
            text = resp.choices[0].message.content or ""
        else:
            resp = client.responses.create(
                model=model,
                input=prompt,
                temperature=0.2,
            )
            text = getattr(resp, "output_text", None)
            if not text:
                # best-effort extraction
                text = str(resp)
    except Exception:
        # Retry with DeepSeek if available and we were using OpenAI.
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

    # Parse bullets into a list of strings
    lines = [ln.strip(" -\t") for ln in text.splitlines() if ln.strip()]
    # keep 3-5
    reasons = [ln for ln in lines if ln][:5]
    if not reasons:
        reasons = [text.strip()[:200]]
    return reasons


# ---- Verdict + scoring helpers ----

def _decide_ai_verdict(phase1: ScanOut, phish_neighbors: List[NeighborOut]) -> str:
    """
    Lightweight verdict logic combining deterministic outcome with neighbor similarity.
    Simple and conservative: strong phish similarity or phase1 phishing -> phishing;
    some phish neighbors -> needs_review; else benign.
    """
    # Immediate pass-through if already phishing
    if phase1.verdict == "phishing":
        return "phishing"

    top_sim = max((n.similarity for n in phish_neighbors), default=0.0)
    avg_top3 = sum(sorted((n.similarity for n in phish_neighbors), reverse=True)[:3]) / max(
        1, min(3, len(phish_neighbors))
    ) if phish_neighbors else 0.0

    if top_sim >= 0.88 or (phase1.verdict == "needs_review" and avg_top3 >= 0.82):
        return "phishing"
    if top_sim >= 0.75 or avg_top3 >= 0.72:
        return "needs_review"
    return phase1.verdict


def _compute_ai_score(phase1: ScanOut, neighbors: List[NeighborOut]) -> int:
    """
    Produce a 0..10 AI score where higher means more likely phishing.
    Derived from nearest-neighbor cosine similarities (top-8) and Phase‑1 verdict.
    - Emphasize phish-labeled neighbors (top and avg top‑3)
    - Add gentle boost from deterministic verdict
    """
    phish_neighbors = [n for n in neighbors if n.label == 1]

    top_overall = max((n.similarity for n in neighbors), default=0.0)
    top_phish = max((n.similarity for n in phish_neighbors), default=0.0)
    avg_top3_phish = (
        sum(sorted((n.similarity for n in phish_neighbors), reverse=True)[:3])
        / max(1, min(3, len(phish_neighbors)))
        if phish_neighbors
        else 0.0
    )

    # Base signal from neighbors: prefer phish-labeled, fallback to overall
    if phish_neighbors:
        neighbor_signal = 0.65 * top_phish + 0.35 * avg_top3_phish
    else:
        neighbor_signal = 0.5 * top_overall

    # Deterministic influence
    phase1_signal = 1.0 if phase1.verdict == "phishing" else (0.6 if phase1.verdict == "needs_review" else 0.0)

    combined = max(neighbor_signal, 0.7 * neighbor_signal + 0.3 * phase1_signal)
    combined = max(0.0, min(1.0, combined))
    return int(round(combined * 10))


# ---- Public API ----

def analyze_email(payload: EmailIn, phase1: ScanOut, *, neighbors_k: int = 8) -> AIAnalyzeOut:
    """
    Perform simple RAG analysis: embed input subject+body, retrieve nearest doc_emb neighbors,
    generate concise explanations via OpenAI Responses API, and return an AI verdict.
    """
    doc_text = _combine_subject_body(payload.subject, payload.body)

    try:
        vec = _embed_text(doc_text)
    except Exception:
        # If embeddings are unavailable, return minimal output with deterministic info only
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
            ai_score=phase1.score,  # fall back to deterministic score when AI unavailable
            ai_reasons=ai_reasons,
        )

    neighbors = _nearest_neighbors(vec, limit=neighbors_k)
    for neighbor in neighbors:
        # Redact both subject and body to avoid exposing raw PII from dataset rows
        redacted_subject, subject_counts = redact(neighbor.subject or "")
        redacted_body, body_counts = redact(neighbor.body or "")

        # Merge counts across subject and body
        merged_keys = set(subject_counts.keys()) | set(body_counts.keys())
        merged_counts: dict[str, int] = {k: int(subject_counts.get(k, 0)) + int(body_counts.get(k, 0)) for k in merged_keys}

        neighbor.subject = redacted_subject
        neighbor.body = redacted_body
        neighbor.redactions = RedactionsOut(types=merged_counts, count=sum(merged_counts.values()))

    phish_neighbors = [n for n in neighbors if n.label == 1]

    # Decide verdict first (without exposing previous label to LLM prompt)
    ai_verdict = _decide_ai_verdict(phase1, phish_neighbors)
    ai_label = 1 if ai_verdict == "phishing" else 0

    ai_reasons = _summarize_reasons_with_llm(
        subject=payload.subject,
        body=phase1.redacted_body or payload.body,
        phase1=phase1,
        neighbors=neighbors,
    )

    # Append bold conclusion line summarizing final stance
    inds = phase1.indicators or {}
    dmarc_policy = str(inds.get("dmarc_policy", "none"))
    # Keep local similarity context minimal; no percentage exposure in UI
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
    )
