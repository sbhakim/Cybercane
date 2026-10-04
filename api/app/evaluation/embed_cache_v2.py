"""
Sanitized-text and embedding cache for the v2 splits.

Every v2 row is sanitized once through the privacy boundary and embedded once
per model. Experiments look rows up by `row_uid`, so all methods and seeds use
identical sanitized text and vectors.

Outputs (WS/cache_v2/):
  sanitized_{family}.csv           row_uid, san_hash, sanitized text, redaction counts
  emb_{model_tag}_{family}.npy     float32 [n_unique, dim], unit-normalized
  emb_{model_tag}_{family}.idx.csv san_hash -> row index in the .npy

Usage:
  PYTHONPATH=api python -m app.evaluation.embed_cache_v2 --stage sanitize
  PYTHONPATH=api python -m app.evaluation.embed_cache_v2 --stage embed --model openai:text-embedding-3-small
  PYTHONPATH=api python -m app.evaluation.embed_cache_v2 --stage embed --model local:BAAI/bge-base-en-v1.5
"""

import argparse
import hashlib
import json
import os
import re
import time
from pathlib import Path

import numpy as np
import pandas as pd

from app.privacy.boundary import REDACTOR_VERSION, sanitize_for_external, truncate_for_embedding

WS = Path(os.environ.get("CYBERCANE_WS", Path(__file__).resolve().parents[3] / "workspace"))
SPLITS = WS / "datasets_v2"
CACHE = WS / "cache_v2"
FAMILIES = ("nazsa", "dataphish")


def row_uid(r) -> str:
    key = f"{r.source}|{r.subject}|{r.body}|{getattr(r, 'orig_id', '')}"
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:24]


def load_family_rows(family: str) -> pd.DataFrame:
    parts = [pd.read_csv(SPLITS / f"{family}_seed42_{s}.csv") for s in ("train", "val", "test")]
    df = pd.concat(parts, ignore_index=True)
    df["subject"] = df["subject"].fillna("").astype(str)
    df["body"] = df["body"].fillna("").astype(str)
    if "orig_id" not in df.columns:
        df["orig_id"] = ""
    df["row_uid"] = [row_uid(r) for r in df.itertuples()]
    return df.drop_duplicates("row_uid").reset_index(drop=True)


def stage_sanitize(families=FAMILIES) -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    for family in families:
        df = load_family_rows(family)
        out, t0 = [], time.time()
        for i, r in enumerate(df.itertuples()):
            text, rep = sanitize_for_external(r.subject, r.body)
            out.append(dict(row_uid=r.row_uid, san_hash=hashlib.sha256(text.encode()).hexdigest()[:24],
                            sanitized=text, ner_used=rep.ner_used, redactions=json.dumps(rep.counts)))
            if (i + 1) % 2000 == 0:
                print(f"  {family}: {i + 1}/{len(df)} ({time.time() - t0:.0f}s)")
        res = pd.DataFrame(out)
        assert res.ner_used.all(), "NER was unavailable for some rows; refusing to write a mixed cache"
        res.to_csv(CACHE / f"sanitized_{family}.csv", index=False)
        print(f"{family}: {len(res)} rows, {res.san_hash.nunique()} unique sanitized texts")
    name = "sanitize_manifest.json" if tuple(families) == FAMILIES else f"sanitize_manifest_{'_'.join(families)}.json"
    (CACHE / name).write_text(json.dumps(
        dict(redactor_version=REDACTOR_VERSION, ner_model=os.getenv("CYBERCANE_NER_MODEL", "dslim/bert-base-NER"),
             split_manifest_sha256=hashlib.sha256((SPLITS / ("split_manifest.json" if tuple(families) == FAMILIES else "split_manifest_benign_extra.json")).read_bytes()).hexdigest()),
        indent=2))


def _embed_openai(texts, model):
    from openai import OpenAI

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    vecs = []
    for start in range(0, len(texts), 100):
        batch = [truncate_for_embedding(t) if t.strip() else "(empty)" for t in texts[start:start + 100]]
        for attempt in range(5):
            try:
                resp = client.embeddings.create(model=model, input=batch)
                vecs.extend(d.embedding for d in resp.data)
                break
            except Exception as exc:
                if attempt == 4:
                    raise
                m = re.search(r"input\[(\d+)\]': maximum input length", str(exc))
                if m:
                    # Estimate was too optimistic for this item: halve it and retry.
                    j = int(m.group(1))
                    batch[j] = batch[j][: len(batch[j]) // 2]
                    print(f"  halved input {start + j} to {len(batch[j])} chars")
                    continue
                print(f"  retry {attempt + 1}: {exc}")
                time.sleep(2 ** attempt)
        if (start // 100) % 20 == 0:
            print(f"  embedded {min(start + 100, len(texts))}/{len(texts)}")
    return np.asarray(vecs, dtype=np.float32)


def _embed_local(texts, model):
    from sentence_transformers import SentenceTransformer

    # Conservative defaults: a full-load GPU job once coincided with a power loss on the dev machine.
    device = os.getenv("CYBERCANE_EMBED_DEVICE", "cpu")
    st = SentenceTransformer(model, device=device)
    st.max_seq_length = int(os.getenv("CYBERCANE_EMBED_MAX_TOKENS", "512"))
    return st.encode(texts, batch_size=int(os.getenv("CYBERCANE_EMBED_BATCH", "16")), normalize_embeddings=True,
                     show_progress_bar=False, convert_to_numpy=True).astype(np.float32)


def stage_embed(model_spec: str, families=FAMILIES, limit: int = 0) -> None:
    provider, model = model_spec.split(":", 1)
    tag = model.split("/")[-1]
    for family in families:
        san = pd.read_csv(CACHE / f"sanitized_{family}.csv", keep_default_na=False)
        uniq = san.drop_duplicates("san_hash").reset_index(drop=True)
        texts = uniq.sanitized.tolist()
        if limit:
            t0 = time.time()
            v = _embed_local(texts[:limit], model)
            print(f"pilot {family}: {v.shape} in {time.time() - t0:.1f}s (nothing written)")
            return
        vecs = _embed_openai(texts, model) if provider == "openai" else _embed_local(texts, model)
        vecs /= np.linalg.norm(vecs, axis=1, keepdims=True).clip(min=1e-12)
        np.save(CACHE / f"emb_{tag}_{family}.npy", vecs)
        uniq[["san_hash"]].assign(idx=range(len(uniq))).to_csv(CACHE / f"emb_{tag}_{family}.idx.csv", index=False)
        print(f"{family}: {vecs.shape} -> emb_{tag}_{family}.npy")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["sanitize", "embed"], required=True)
    ap.add_argument("--model", default="openai:text-embedding-3-small")
    ap.add_argument("--families", nargs="+", default=list(FAMILIES))
    ap.add_argument("--limit", type=int, default=0, help="pilot: embed only the first N texts, write nothing")
    args = ap.parse_args()
    fams = tuple(args.families)
    stage_sanitize(fams) if args.stage == "sanitize" else stage_embed(args.model, fams, args.limit)


if __name__ == "__main__":
    main()
