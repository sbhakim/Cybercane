"""
Load a leak-free, sanitized retrieval corpus into the app_v2 database

Only rows of the TRAIN split for the given seed are inserted. Text columns hold
privacy-boundary output only; embeddings come from the v2 cache
(`app.evaluation.embed_cache_v2`), so no provider call happens here.

Usage:
  DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:5432/app_v2 \
  PYTHONPATH=api python -m app.scripts.build_corpus_v2 --seed 42
"""

import argparse
import os

import numpy as np
import pandas as pd
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

from app.evaluation.embed_cache_v2 import CACHE, SPLITS, row_uid
from app.evaluation.label_policy import task_label
from app.privacy.boundary import REDACTOR_VERSION

EMBED_TAG = "text-embedding-3-small"


def load_train(family: str, seed: int) -> pd.DataFrame:
    df = pd.read_csv(SPLITS / f"{family}_seed{seed}_train.csv")
    df["subject"] = df["subject"].fillna("").astype(str)
    df["body"] = df["body"].fillna("").astype(str)
    if "orig_id" not in df.columns:
        df["orig_id"] = ""
    df["row_uid"] = [row_uid(r) for r in df.itertuples()]
    df = df.drop_duplicates("row_uid")
    san = pd.read_csv(CACHE / f"sanitized_{family}.csv", keep_default_na=False)
    idx = pd.read_csv(CACHE / f"emb_{EMBED_TAG}_{family}.idx.csv")
    df = df.merge(san[["row_uid", "san_hash", "sanitized"]], on="row_uid", how="left", validate="one_to_one")
    assert df.san_hash.notna().all(), "rows missing from sanitized cache"
    df = df.merge(idx, on="san_hash", how="left", validate="many_to_one")
    assert df.idx.notna().all(), "rows missing from embedding cache"
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    url = os.environ["DATABASE_URL"]
    assert url.rstrip("/").endswith("/app_v2"), "refusing to load into a database other than app_v2"
    engine = sa.create_engine(url)

    stmt = sa.text("""
        INSERT INTO messages (sender_email, subject, body, redacted_body, urls, label, doc_emb,
                              message_hash, row_uid, split, split_seed, source, fine_class,
                              dedup_group, redactor_version, embed_model)
        VALUES ('', :subject, :body, :body, :urls, :label, :emb,
                :mhash, :row_uid, 'train', :seed, :source, :fine,
                :group, :rv, :em)
    """).bindparams(sa.bindparam("emb", type_=Vector(1536)))

    with engine.begin() as conn:
        n_existing = conn.execute(sa.text("SELECT count(*) FROM messages WHERE split_seed = :s"),
                                  {"s": args.seed}).scalar()
        assert n_existing == 0, f"seed {args.seed} already loaded ({n_existing} rows)"
        for family in ("nazsa", "dataphish"):
            df = load_train(family, args.seed)
            vecs = np.load(CACHE / f"emb_{EMBED_TAG}_{family}.npy")
            rows = []
            for r in df.itertuples():
                subj, _, body = r.sanitized.partition("\n\n")
                rows.append(dict(
                    subject=subj, body=body, urls=int(r.urls), label=task_label(r.fine, "phish"),
                    emb=vecs[int(r.idx)].tolist(), mhash=f"{r.row_uid}:{args.seed}", row_uid=r.row_uid,
                    seed=args.seed, source=r.source, fine=r.fine, group=f"{family}:{r.group}",
                    rv=REDACTOR_VERSION, em=EMBED_TAG))
            for start in range(0, len(rows), 500):
                conn.execute(stmt, rows[start:start + 500])
            print(f"{family}: inserted {len(rows)} train rows")
    # Without fresh statistics the planner skips the cosine HNSW index after a bulk load.
    with engine.connect() as conn:
        conn.execution_options(isolation_level="AUTOCOMMIT").execute(sa.text("ANALYZE messages"))
    print("analyzed messages")


if __name__ == "__main__":
    main()
