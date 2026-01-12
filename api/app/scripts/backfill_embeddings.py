from __future__ import annotations

import argparse
import os
from typing import Iterable, List, Tuple

import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.engine import Connection

from pgvector.sqlalchemy import Vector

from app.db import engine


def build_inputs_for_target(rows: List[tuple], target: str) -> Tuple[List[int], List[str]]:
    ids: List[int] = []
    inputs: List[str] = []

    if target == "doc":
        for _id, subject, body in rows:
            text_value = f"{subject or ''}\n\n{body or ''}".strip()
            if text_value:
                ids.append(_id)
                # keep a reasonable cap to avoid oversized payloads
                inputs.append(text_value[:8000])
    elif target == "subject":
        for _id, subject in rows:
            text_value = (subject or "").strip()
            if text_value:
                ids.append(_id)
                inputs.append(text_value[:8000])
    elif target == "body":
        for _id, body in rows:
            text_value = (body or "").strip()
            if text_value:
                ids.append(_id)
                inputs.append(text_value[:8000])
    elif target == "url":
        for _id, url in rows:
            text_value = (url or "").strip()
            if text_value:
                ids.append(_id)
                inputs.append(text_value[:8000])
    else:
        raise ValueError(f"Unknown target: {target}")
    return ids, inputs


def fetch_rows(conn: Connection, target: str, batch_size: int) -> List[tuple]:
    if target == "doc":
        stmt = text(
            """
            SELECT id, subject, body
            FROM messages
            WHERE doc_emb IS NULL
            ORDER BY id
            LIMIT :lim
            """
        )
    elif target == "subject":
        stmt = text(
            """
            SELECT id, subject
            FROM messages
            WHERE subject IS NOT NULL AND subject <> '' AND subject_emb IS NULL
            ORDER BY id
            LIMIT :lim
            """
        )
    elif target == "body":
        stmt = text(
            """
            SELECT id, body
            FROM messages
            WHERE body IS NOT NULL AND body <> '' AND body_emb IS NULL
            ORDER BY id
            LIMIT :lim
            """
        )
    elif target == "url":
        stmt = text(
            """
            SELECT id, url_extracted
            FROM messages
            WHERE url_extracted IS NOT NULL AND url_extracted <> '' AND url_emb IS NULL
            ORDER BY id
            LIMIT :lim
            """
        )
    else:
        raise ValueError(f"Unknown target: {target}")

    return list(conn.execute(stmt, {"lim": batch_size}).fetchall())


def update_embeddings(
    conn: Connection,
    target: str,
    ids: List[int],
    vectors: List[List[float]],
) -> None:
    if not ids:
        return
    if target == "doc":
        stmt = sa.text("UPDATE messages SET doc_emb = :emb WHERE id = :id")
    elif target == "subject":
        stmt = sa.text("UPDATE messages SET subject_emb = :emb WHERE id = :id")
    elif target == "body":
        stmt = sa.text("UPDATE messages SET body_emb = :emb WHERE id = :id")
    elif target == "url":
        stmt = sa.text("UPDATE messages SET url_emb = :emb WHERE id = :id")
    else:
        raise ValueError(f"Unknown target: {target}")

    # Ensure pgvector bind type so SQLAlchemy encodes correctly
    stmt = stmt.bindparams(sa.bindparam("emb", type_=Vector(1536)))

    for _id, vec in zip(ids, vectors):
        conn.execute(stmt, {"id": _id, "emb": vec})


def embed_batch(model: str, inputs: List[str]) -> List[List[float]]:
    # Lazy import to avoid requiring OpenAI for non-embedding paths
    try:
        from openai import OpenAI
    except Exception as e:
        raise RuntimeError(
            "openai package not available. Rebuild the api image after updating requirements.txt"
        ) from e

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set in api container")

    client = OpenAI(api_key=api_key)
    resp = client.embeddings.create(model=model, input=inputs)
    return [d.embedding for d in resp.data]


def run_backfill(target: str, batch_size: int, limit: int | None, model: str) -> None:
    total_done = 0
    with engine.begin() as conn:
        while True:
            rows = fetch_rows(conn, target, min(batch_size, (limit - total_done) if limit else batch_size))
            if not rows:
                break
            ids, inputs = build_inputs_for_target(rows, target)
            if not ids:
                break
            vectors = embed_batch(model, inputs)
            update_embeddings(conn, target, ids, vectors)
            total_done += len(ids)
            print(f"updated {len(ids)} {target} embeddings (total={total_done})")
            if limit and total_done >= limit:
                break
    print(f"done. total {target} embeddings updated: {total_done}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill pgvector embeddings for messages")
    parser.add_argument(
        "--target",
        choices=["doc", "subject", "body", "url"],
        default="doc",
        help="Which embedding column to fill",
    )
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--limit", type=int, default=None, help="Max rows to process (default: all)")
    parser.add_argument(
        "--model",
        default="text-embedding-3-small",
        help="OpenAI embeddings model (1536 dims recommended)",
    )
    args = parser.parse_args()

    run_backfill(args.target, args.batch_size, args.limit, args.model)


if __name__ == "__main__":
    main()


