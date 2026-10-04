"""
E1: generate the explanations for the human audit (protocol fixed before any run).

Stage 1 (pool):  320 candidate test emails -> Phase 1 (live DNS), query embedding, neighbors, calibrated verdict.
Stage 2 (items): 120 emails drawn by outcome cell (TP/FN/FP/TN/REVIEW, 24 each); analyze_email runs twice per
                 email (ontology context on/off) with gpt-4.1-mini; 240 shuffled, blinded Task A items.

The deployed code path is used as is. Two substitutions, neither changing a computation:
  * _nearest_neighbors -> exact cosine top-k over cached text-embedding-3-small vectors of all train-split
    phishing (DataPhish + Nazario), instead of the pgvector index;
  * DNS lookups are memoized per domain so both variants of an email see identical sender checks.

Run (project env, OPENAI_API_KEY set):
  RISK_THRESHOLDS_PATH=../config/risk_thresholds_nazario_spamassassin_seed42.json \
    python -m app.evaluation.e1_explanations pool|items
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

WS = Path(os.environ.get("CYBERCANE_WS", Path(__file__).resolve().parents[3] / "workspace"))
HA = Path(os.environ.get("CYBERCANE_ANNOT_DIR", WS / "annotations"))
OUT = HA / "data"
POOL = OUT / "task_a_pool.jsonl"
SEED = 20261005
POOL_STRATA = [("dataphish", "phishing", 70), ("dataphish", "legit", 70), ("nazsa", "phishing", 70),
               ("nazsa", "legit", 70), ("ceas", "legit", 40)]
CELLS, PER_CELL, K = ("TP", "FN", "FP", "TN", "REVIEW"), 24, 8
MIN_GAP = 20

assert os.getenv("RISK_THRESHOLDS_PATH"), "set RISK_THRESHOLDS_PATH to the calibrated 1% thresholds"
from app.ai_service import service  # noqa: E402  (reads RISK_THRESHOLDS_PATH at import)
from app.pipeline import deterministic  # noqa: E402
from app.pipeline.classify import classify_email  # noqa: E402
from app.schemas import EmailIn, NeighborOut, ScanOut  # noqa: E402
assert service.RISK_THRESHOLDS is not None, "calibrated thresholds did not load"


def row_uid(r) -> str:   # identical to app.evaluation.embed_cache_v2.row_uid
    key = f"{r.source}|{r.subject}|{r.body}|{getattr(r, 'orig_id', '')}"
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:24]


def read(fam: str, split: str) -> pd.DataFrame:
    d = pd.read_csv(WS / "datasets_v2" / f"{fam}_seed42_{split}.csv")
    for c in ("subject", "body", "sender"):
        d[c] = d[c].fillna("").astype(str)
    if "orig_id" not in d.columns:
        d["orig_id"] = ""
    d["orig_id"] = d.orig_id.fillna("")
    d["row_uid"] = [row_uid(r) for r in d.itertuples()]
    return d


# ---------------------------------------------------------------- substitutions
def _corpus():
    rows, vecs = [], []
    for fam in ("dataphish", "nazsa"):
        d = read(fam, "train")
        d = d[d.fine == "phishing"].drop_duplicates("row_uid")
        san = pd.read_csv(WS / "cache_v2" / f"sanitized_{fam}.csv", keep_default_na=False)
        idx = pd.read_csv(WS / "cache_v2" / f"emb_text-embedding-3-small_{fam}.idx.csv")
        d = d.merge(san[["row_uid", "san_hash"]], on="row_uid", validate="one_to_one").merge(idx, on="san_hash", validate="many_to_one")
        vecs.append(np.load(WS / "cache_v2" / f"emb_text-embedding-3-small_{fam}.npy")[d.idx.values.astype(int)])
        rows.append(d[["subject", "body"]])
    X = np.vstack(vecs).astype(np.float32)
    return pd.concat(rows, ignore_index=True), X / np.linalg.norm(X, axis=1, keepdims=True)


CORPUS, CX = _corpus()


def nearest_neighbors(vec, limit: int = 8, *, include_benign: bool = False):
    q = np.asarray(vec, dtype=np.float32); q /= np.linalg.norm(q)
    s = CX @ q
    top = np.argsort(-s)[:limit]
    return [NeighborOut(id=int(i), label=1, subject=CORPUS.subject[i], body=CORPUS.body[i], similarity=float(s[i])) for i in top]


service._nearest_neighbors = nearest_neighbors
deterministic._auth_results_for_domain = functools.cache(deterministic._auth_results_for_domain)
service._embed_text = functools.cache(service._embed_text)


# The service silently falls back to DeepSeek when OpenAI fails; E1 is preregistered on gpt-4.1-mini only, so the
# fallback is disabled (a failure becomes the service's own "AI API call failed" text and is counted) and transient
# OpenAI errors are retried. The model version string of every response is logged.
MODELS: list[str] = []
_orig_build = service._build_ai_client


class _Retrying:
    def __init__(self, client):
        self._c = client

    def create(self, **kw):
        for k in range(5):
            try:
                r = self._c.responses.create(**kw); MODELS.append(getattr(r, "model", "?")); return r
            except Exception as e:  # noqa: BLE001
                if k == 4:
                    raise
                print("  retry", type(e).__name__, file=sys.stderr); time.sleep(2 ** k * 3)


class _Client:
    def __init__(self, c):
        self._c, self.responses = c, _Retrying(c)

    def __getattr__(self, name):      # embeddings and anything else go straight to the OpenAI client
        return getattr(self._c, name)


def build_ai_client(prefer_deepseek: bool = False):
    if prefer_deepseek:
        raise RuntimeError("DeepSeek fallback disabled for E1")
    c, p = _orig_build(False)
    assert p == "openai", p
    return _Client(c), p


service._build_ai_client = build_ai_client


# ---------------------------------------------------------------- stage 1
def excluded() -> set:
    ex = set(pd.read_csv(HA / "data" / "task_b_emails.csv").row_uid)
    for fam in ("dataphish", "nazsa"):                          # P1's 200 base emails (p1_planted_redaction)
        d = read(fam, "test")
        for lab in ("phishing", "legit"):
            ex |= set(d[d.fine == lab].sample(50, random_state=20261003).row_uid)
    assert len(ex) == 300, len(ex)
    return ex


def payload(r) -> dict:
    return {"sender": r["sender"], "receiver": "", "subject": r["subject"], "body": r["body"], "url": int(r["urls"])}


def stage_pool():
    ex, frames = excluded(), []
    for fam, lab, n in POOL_STRATA:
        d = read(fam, "test")
        d = d[(d.fine == lab) & d.body.str.len().between(80, 2000) & ~d.row_uid.isin(ex) & (d.sender != "")]
        frames.append(d.drop_duplicates("row_uid").sample(n, random_state=SEED).assign(family=fam))
    pool = pd.concat(frames, ignore_index=True)
    done = {json.loads(l)["row_uid"] for l in POOL.read_text().splitlines()} if POOL.exists() else set()
    with POOL.open("a") as f:
        for i, r in pool.iterrows():
            if r.row_uid in done:
                continue
            p1 = classify_email(payload(r))
            vec = service._embed_text(service.sanitize_for_external(r.subject, r.body)[0])
            nb = nearest_neighbors(vec, K)
            risk = service._compute_ai_risk(p1, nb)
            verdict = service.decide(risk, p1.verdict, service.RISK_THRESHOLDS)
            f.write(json.dumps({"row_uid": r.row_uid, "family": r.family, "label": r.fine, "sender": r.sender, "subject": r.subject,
                                "body": r.body, "urls": int(r.urls), "phase1": p1.model_dump(), "risk": risk, "verdict": verdict,
                                "dns_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}) + "\n")
            f.flush()
            if i % 20 == 0:
                print(f"pool {i + 1}/{len(pool)}", flush=True)
    show_cells()


def cell(r) -> str:
    if r["verdict"] == "needs_review":
        return "REVIEW"
    phish, called = r["label"] == "phishing", r["verdict"] == "phishing"
    return {(True, True): "TP", (True, False): "FN", (False, True): "FP", (False, False): "TN"}[(phish, called)]


def load_pool() -> pd.DataFrame:
    p = pd.DataFrame([json.loads(l) for l in POOL.read_text().splitlines()])
    p["cell"] = p.apply(cell, axis=1)
    return p


def show_cells():
    p = load_pool()
    print(pd.crosstab([p.family, p.label], p.cell, margins=True).to_string())


# ---------------------------------------------------------------- stage 2
def select(p: pd.DataFrame) -> pd.DataFrame:
    take, short = {}, 0
    for c in CELLS:
        g = p[p.cell == c]
        take[c] = min(PER_CELL, len(g)); short += PER_CELL - take[c]
    for c in ("TP", "TN"):                                     # shortfall filled in equal parts from TP and TN
        take[c] += short // 2 + (short % 2 if c == "TP" else 0)
    picks = []
    for c in CELLS:
        g = p[p.cell == c]
        assert len(g) >= take[c], f"cell {c}: need {take[c]}, have {len(g)}"
        picks.append(g.sample(take[c], random_state=SEED))
    s = pd.concat(picks, ignore_index=True)
    assert len(s) == 120, len(s)
    print("selected per cell:", s.cell.value_counts().reindex(CELLS).to_dict())
    return s


def shuffle_order(n_emails: int) -> list:
    """Seeded shuffle of the 2n explanations, then seeded repair swaps until the two explanations of every email are
    >= MIN_GAP positions apart (pure rejection sampling essentially never succeeds for 120 pairs)."""
    rng = np.random.default_rng(SEED)
    perm = list(rng.permutation(2 * n_emails))             # entry j -> (email j // 2, variant j % 2)
    for _ in range(100_000):
        pos = {j: k for k, j in enumerate(perm)}
        bad = [e for e in range(n_emails) if abs(pos[2 * e] - pos[2 * e + 1]) < MIN_GAP]
        if not bad:
            return perm
        e = bad[int(rng.integers(len(bad)))]
        a, b = pos[2 * e + int(rng.integers(2))], int(rng.integers(2 * n_emails))
        perm[a], perm[b] = perm[b], perm[a]
    raise RuntimeError("no permutation met the gap constraint")


def stage_items(limit: int = 0):
    sel = select(load_pool())
    gen_path = OUT / "task_a_generations.jsonl"
    gens = {(g["row_uid"], g["ontology_context"]): g for g in map(json.loads, gen_path.read_text().splitlines())} if gen_path.exists() else {}
    perm = shuffle_order(len(sel))
    with gen_path.open("a") as f:
        for k, j in enumerate(perm):                           # study order, so a staged release has its items first
            r, onto = sel.iloc[int(j) // 2], bool(j % 2 == 0)
            p1 = ScanOut(**r.phase1)
            if (r.row_uid, onto) not in gens:
                n0 = len(MODELS)
                out = service.analyze_email(EmailIn(sender=r.sender, subject=r.subject, body=r.body, url=r.urls), p1,
                                            include_ontology_context=onto)
                g = {"row_uid": r.row_uid, "ontology_context": onto, "model": MODELS[n0] if len(MODELS) > n0 else None,
                     "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "analysis": out.model_dump()}
                gens[(r.row_uid, onto)] = g
                f.write(json.dumps(g) + "\n"); f.flush()
            if limit and k + 1 >= limit:
                break
            print(f"item {k + 1}/240", flush=True)
    write_items(sel, gens, limit)


def bullets_of(analysis: dict) -> list:
    return [b for b in analysis["ai_reasons"] if not b.startswith("Conclusion:")]


def write_items(sel: pd.DataFrame, gens: dict, limit: int = 0):
    perm, items, key = shuffle_order(len(sel)), [], []
    perm = perm[:limit] if limit else perm
    vmap = {"needs_review": "review", "phishing": "phishing", "benign": "benign"}
    for k, j in enumerate(perm):
        r, onto = sel.iloc[int(j) // 2], bool(j % 2 == 0)
        a = gens[(r.row_uid, onto)]["analysis"]
        p1, nb = a["phase1"], a["neighbors"]
        sims = sorted((n["similarity"] for n in nb), reverse=True)
        ind = p1["indicators"] or {}
        yn = lambda v: "yes" if v else "no"  # noqa: E731
        subj, body = service.sanitize_field(r.subject)[0], service.sanitize_field(r.body)[0]
        iid = f"A{k + 1:03d}"
        items.append({
            "task": "A", "practice": False, "order": k + 1, "id": iid, "verdict": vmap[a["ai_verdict"]],
            "email": f"Subject: {subj}\n\n{body}",
            "evidence": {
                "violations": list(p1["reasons"]),
                "technical": {"sender_domain": ind.get("sender_domain") or "", "mx": yn(ind.get("has_mx")), "spf": yn(ind.get("spf_present")),
                              "dmarc": yn(ind.get("dmarc_present")), "dmarc_policy": ind.get("dmarc_policy", "none")},
                "retrieval": {"top_sim": round(sims[0], 4) if sims else None, "avg_top3": round(float(np.mean(sims[:3])), 4) if sims else None,
                              "avg_all": round(float(np.mean(sims)), 4) if sims else None,
                              "neighbors": [{"subject": n["subject"], "sim": round(n["similarity"], 4)} for n in nb[:3]]},
                "ontology": {"asserted": [o["attack_type"] for o in (a.get("ontology_attacks") or [])],
                             "suggested": [o["attack_type"] for o in (a.get("ontology_suggestions") or [])]},
            },
            "bullets": bullets_of(a),
        })
        key.append({"item": iid, "row_uid": r.row_uid, "family": r.family, "label": r.label, "cell": r.cell,
                    "ontology_context": onto, "verdict": a["ai_verdict"], "n_bullets": len(bullets_of(a)),
                    "failed": any("AI API call failed" in b or "AI client unavailable" in b for b in a["ai_reasons"])})
    (OUT / "task_a_items.json").write_text(json.dumps(items, ensure_ascii=False, indent=1))
    pd.DataFrame(key).to_csv(OUT / "task_a_key.csv", index=False)       # private: variant mapping, never uploaded
    k = pd.DataFrame(key)
    print(f"wrote {len(items)} items; bullets {k.n_bullets.sum()}; failed {int(k.failed.sum())}; models {sorted(set(MODELS))}")


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "items":
        stage_items(int(sys.argv[2]) if len(sys.argv) > 2 else 0)   # e.g. `items 20` = staged release A001-A020
    else:
        {"pool": stage_pool, "cells": show_cells}[cmd]()
