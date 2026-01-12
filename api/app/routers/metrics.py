from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from typing import Any, Dict, List
from datetime import datetime
import os

from app.db import engine


router = APIRouter()


@router.get("/overview")
def metrics_overview() -> dict:
    """
    Return concise dataset/DB readiness metrics derived from messages table.
    Safe to call even when DB is empty or temporarily unavailable.
    """
    try:
        with engine.connect() as conn:
            totals_row = conn.execute(
                text(
                    """
                    SELECT
                      COUNT(*) AS total,
                      SUM(CASE WHEN label = 1 THEN 1 ELSE 0 END) AS label_1,
                      SUM(CASE WHEN label = 0 THEN 1 ELSE 0 END) AS label_0,
                      SUM(CASE WHEN label IS NULL THEN 1 ELSE 0 END) AS unlabeled,
                      SUM(CASE WHEN urls = 1 THEN 1 ELSE 0 END) AS urls_1,
                      COUNT(doc_emb) AS doc_emb,
                      COUNT(subject_emb) AS subject_emb,
                      COUNT(body_emb) AS body_emb,
                      COUNT(url_emb) AS url_emb
                    FROM messages
                    """
                )
            ).mappings().first()

            total = int(totals_row["total"]) if totals_row else 0

            # Top sender domains (max 5)
            top_domains = [
                {"domain": r["sender_domain"], "count": int(r["cnt"])}
                for r in conn.execute(
                    text(
                        """
                        SELECT sender_domain, COUNT(*) AS cnt
                        FROM messages
                        WHERE sender_domain IS NOT NULL AND sender_domain <> ''
                        GROUP BY sender_domain
                        ORDER BY cnt DESC
                        LIMIT 5
                        """
                    )
                ).mappings()
            ]

            # Text length medians (subject/body)
            medians = conn.execute(
                text(
                    """
                    SELECT
                      (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY length(subject))
                         FROM messages WHERE subject IS NOT NULL AND subject <> '') AS subject_median,
                      (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY length(body))
                         FROM messages WHERE body IS NOT NULL AND body <> '') AS body_median,
                      (SELECT percentile_cont(0.25) WITHIN GROUP (ORDER BY length(subject))
                         FROM messages WHERE subject IS NOT NULL AND subject <> '') AS subject_p25,
                      (SELECT percentile_cont(0.75) WITHIN GROUP (ORDER BY length(subject))
                         FROM messages WHERE subject IS NOT NULL AND subject <> '') AS subject_p75,
                      (SELECT percentile_cont(0.25) WITHIN GROUP (ORDER BY length(body))
                         FROM messages WHERE body IS NOT NULL AND body <> '') AS body_p25,
                      (SELECT percentile_cont(0.75) WITHIN GROUP (ORDER BY length(body))
                         FROM messages WHERE body IS NOT NULL AND body <> '') AS body_p75
                    """
                )
            ).mappings().first() or {}

            label_1 = int(totals_row["label_1"]) if totals_row else 0
            label_0 = int(totals_row["label_0"]) if totals_row else 0
            unlabeled = int(totals_row["unlabeled"]) if totals_row else 0
            urls_1 = int(totals_row["urls_1"]) if totals_row else 0

            doc_emb = int(totals_row["doc_emb"]) if totals_row else 0
            subject_emb = int(totals_row["subject_emb"]) if totals_row else 0
            body_emb = int(totals_row["body_emb"]) if totals_row else 0
            url_emb = int(totals_row["url_emb"]) if totals_row else 0

            percent_with_url = (urls_1 / total * 100.0) if total > 0 else 0.0

            return {
                "total": total,
                "labels": {"label_1": label_1, "label_0": label_0, "unlabeled": unlabeled},
                "urls": {"with_url": urls_1, "percent_with_url": percent_with_url},
                "top_sender_domains": top_domains,
                "lengths": {
                    "subject_median": float(medians.get("subject_median") or 0.0),
                    "subject_p25": float(medians.get("subject_p25") or 0.0),
                    "subject_p75": float(medians.get("subject_p75") or 0.0),
                    "body_median": float(medians.get("body_median") or 0.0),
                    "body_p25": float(medians.get("body_p25") or 0.0),
                    "body_p75": float(medians.get("body_p75") or 0.0),
                },
                "embeddings": {
                    "doc": doc_emb,
                    "subject": subject_emb,
                    "body": body_emb,
                    "url": url_emb,
                },
            }
    except Exception:
        # Graceful fallback for demo environments without DB
        return {
            "total": 0,
            "labels": {"label_1": 0, "label_0": 0, "unlabeled": 0},
            "urls": {"with_url": 0, "percent_with_url": 0.0},
            "top_sender_domains": [],
            "lengths": {
                "subject_median": 0.0,
                "subject_p25": 0.0,
                "subject_p75": 0.0,
                "body_median": 0.0,
                "body_p25": 0.0,
                "body_p75": 0.0,
            },
            "embeddings": {"doc": 0, "subject": 0, "body": 0, "url": 0},
        }



class SimilarIn(BaseModel):
    subject: str = ""
    body: str = ""
    k: int = 5
    model: str = "text-embedding-3-small"


def _embed_doc(subject: str, body: str, model: str) -> List[float]:
    try:
        from openai import OpenAI  # lazy import
    except Exception as e:
        raise RuntimeError("openai package not available in api image") from e

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")

    text = f"{subject or ''}\n\n{body or ''}".strip()[:8000]
    client = OpenAI(api_key=api_key)
    resp = client.embeddings.create(model=model, input=[text])
    return list(resp.data[0].embedding)


@router.post("/similar")
def metrics_similar(req: SimilarIn) -> Dict[str, Any]:
    """
    Return top-k nearest labeled=1 (phish) messages by cosine similarity on `doc_emb`.
    Requires OPENAI_API_KEY to compute the query embedding.
    """
    try:
        query_vec = _embed_doc(req.subject, req.body, req.model)
    except Exception as e:
        return {
            "error": "Embedding error",
            "detail": str(e),
            "items": [],
        }

    try:
        with engine.connect() as conn:
            # Optional search tuning for better recall
            try:
                conn.execute(text("SET hnsw.ef_search = 100"))
            except Exception:
                pass

            stmt = sa.text(
                """
                SELECT
                  id,
                  sender,
                  sender_email,
                  sender_domain,
                  subject,
                  body,
                  label,
                  verdict,
                  score,
                  reasons,
                  indicators,
                  1 - (doc_emb <-> :q) AS similarity
                FROM messages
                WHERE doc_emb IS NOT NULL AND label = 1
                ORDER BY doc_emb <-> :q
                LIMIT :k
                """
            ).bindparams(sa.bindparam("q", type_=Vector(1536)))

            rows = list(
                conn.execute(stmt, {"q": query_vec, "k": int(max(1, min(25, req.k)))})
            )

            items: List[Dict[str, Any]] = []
            for r in rows:
                body_preview = (r.body or "")[:240]
                items.append(
                    {
                        "id": int(r.id),
                        "sender": r.sender,
                        "sender_email": r.sender_email,
                        "sender_domain": r.sender_domain,
                        "subject": r.subject,
                        "body_preview": body_preview,
                        "label": int(r.label) if r.label is not None else None,
                        "verdict": r.verdict,
                        "score": int(r.score) if r.score is not None else None,
                        "reasons": r.reasons or [],
                        "indicators": r.indicators or {},
                        "similarity": float(r.similarity or 0.0),
                    }
                )

            return {"items": items}
    except Exception as e:
        return {"error": "DB query failed", "detail": str(e), "items": []}


@router.get("/ugly")
def metrics_ugly(limit: int = 10) -> Dict[str, Any]:
    """
    Return the "ugliest" phishing examples for UI demos.
    Heuristic: label=1 ordered by a mix of high urgency, link presence, and short subject.
    Falls back to recent known phish if indicators aren't available.
    """
    try:
        with engine.connect() as conn:
            stmt = text(
                """
                SELECT id, sender, sender_email, sender_domain, subject,
                       left(COALESCE(redacted_body, body, ''), 800) AS body,
                       COALESCE(indicators->>'urgency_hits', '0')::int AS urgency,
                       COALESCE(indicators->>'link_count', '0')::int AS link_count,
                       (1 - LEAST(1, GREATEST(0, (length(subject)::float / 120.0)))) AS short_subj
                FROM messages
                WHERE label = 1
                ORDER BY (COALESCE(indicators->>'urgency_hits','0')::int * 2
                          + COALESCE(indicators->>'link_count','0')::int * 1
                          + (1 - LEAST(1, GREATEST(0, (length(subject)::float / 120.0)))) * 1.5) DESC,
                         id DESC
                LIMIT :k
                """
            )
            rows = list(conn.execute(stmt, {"k": int(max(1, min(50, limit)))}))
            items = [
                {
                    "id": int(r.id),
                    "sender": r.sender,
                    "sender_email": r.sender_email,
                    "sender_domain": r.sender_domain,
                    "subject": r.subject,
                    "body": r.body,
                }
                for r in rows
            ]
            return {"items": items}
    except Exception as e:
        return {"error": "DB query failed", "detail": str(e), "items": []}


@router.get("/timeseries")
def metrics_timeseries() -> Dict[str, Any]:
    """
    Daily counts for simple line charts: total, phish, benign.
    """
    try:
        with engine.connect() as conn:
            rows = list(
                conn.execute(
                    text(
                        """
                        SELECT date_trunc('day', COALESCE(msg_date, created_at))::date AS d,
                               COUNT(*) AS total,
                               SUM(CASE WHEN label = 1 THEN 1 ELSE 0 END) AS phish,
                               SUM(CASE WHEN label = 0 THEN 1 ELSE 0 END) AS benign
                        FROM messages
                        GROUP BY d
                        ORDER BY d
                        """
                    )
                )
            )
            return {
                "items": [
                    {"date": str(r.d), "total": int(r.total), "phish": int(r.phish or 0), "benign": int(r.benign or 0)}
                    for r in rows
                ]
            }
    except Exception as e:
        return {"error": "DB query failed", "detail": str(e), "items": []}


@router.get("/length_hist")
def metrics_length_hist() -> Dict[str, Any]:
    """
    Histogram buckets for subject/body lengths.
    """
    try:
        with engine.connect() as conn:
            def _hist(sql: str) -> List[Dict[str, Any]]:
                return [
                    {"bucket": int(r.bucket), "count": int(r.cnt)}
                    for r in conn.execute(text(sql))
                ]

            subject_hist = _hist(
                """
                WITH lens AS (
                  SELECT length(subject) AS l FROM messages WHERE subject IS NOT NULL AND subject <> ''
                )
                SELECT width_bucket(l, 0, 240, 12) AS bucket, COUNT(*) AS cnt
                FROM lens GROUP BY bucket ORDER BY bucket
                """
            )
            body_hist = _hist(
                """
                WITH lens AS (
                  SELECT length(body) AS l FROM messages WHERE body IS NOT NULL AND body <> ''
                )
                SELECT width_bucket(l, 0, 3000, 12) AS bucket, COUNT(*) AS cnt
                FROM lens GROUP BY bucket ORDER BY bucket
                """
            )
            return {"subject": subject_hist, "body": body_hist}
    except Exception as e:
        return {"error": "DB query failed", "detail": str(e)}


@router.get("/examples")
def metrics_examples(limit: int = 25) -> Dict[str, Any]:
    """
    Return random message examples biased toward the most frequent sender domains.
    Strategy:
      1) Compute top 10 sender domains by volume
      2) Randomly sample from those domains to surface representative examples
    Falls back to pure random sample if domains aren't available.
    """
    try:
        with engine.connect() as conn:
            # Top domains (up to 10)
            top_domains_rows = list(
                conn.execute(
                    text(
                        """
                        SELECT sender_domain, COUNT(*) AS cnt
                        FROM messages
                        WHERE sender_domain IS NOT NULL AND sender_domain <> ''
                        GROUP BY sender_domain
                        ORDER BY cnt DESC
                        LIMIT 10
                        """
                    )
                )
            )

            domains = [r.sender_domain for r in top_domains_rows]
            k = int(max(1, min(100, limit)))

            base_sql = """
                SELECT
                  id,
                  sender,
                  sender_email,
                  receiver,
                  sender_domain,
                  subject,
                  LEFT(COALESCE(redacted_body, body, ''), 1200) AS body,
                  label,
                  score,
                  verdict,
                  COALESCE(msg_date, created_at) AS message_ts
                FROM messages
            """

            if domains:
                # Sample prioritized by frequent domains
                stmt = text(
                    base_sql
                    + """
                    WHERE sender_domain = ANY(:domains)
                    ORDER BY random()
                    LIMIT :k
                    """
                )
                rows = list(
                    conn.execute(
                        stmt.bindparams(sa.bindparam("domains", type_=sa.ARRAY(sa.Text()))),
                        {"domains": domains, "k": k},
                    )
                )
            else:
                # Fallback: pure random sample
                rows = list(
                    conn.execute(
                        text(
                            base_sql
                            + """
                            ORDER BY random()
                            LIMIT :k
                            """
                        ),
                        {"k": k},
                    )
                )

            items: List[Dict[str, Any]] = []
            for r in rows:
                message_ts = getattr(r, "message_ts", None)
                if isinstance(message_ts, datetime):
                    iso_ts = message_ts.isoformat()
                elif message_ts is not None:
                    iso_ts = str(message_ts)
                else:
                    iso_ts = None

                items.append(
                    {
                        "id": int(r.id),
                        "sender": r.sender,
                        "sender_email": r.sender_email,
                        "receiver": getattr(r, "receiver", None),
                        "sender_domain": r.sender_domain,
                        "subject": r.subject,
                        "body": r.body,
                        "label": int(r.label) if getattr(r, "label", None) is not None else None,
                        "score": int(r.score) if getattr(r, "score", None) is not None else None,
                        "verdict": getattr(r, "verdict", None),
                        "message_ts": iso_ts,
                    }
                )
            return {"items": items, "domains": domains}
    except Exception as e:
        return {"error": "DB query failed", "detail": str(e), "items": []}