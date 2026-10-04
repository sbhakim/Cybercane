"""
C1 pilot: false-positive budget under distribution shift.

Protocol fixed before the run ("Audit v2").
  Source: Nazario+SpamAssassin v2 (fit / index on train, thresholds on val).
  Target: DataPhish v2 test. Secondary: the reverse direction, and in-domain.
  Budgets: FPR 0.5%, 1%, 2%, thresholds set on SOURCE validation negatives only.
  Methods (all on privacy-boundary text):
    B3   TF-IDF + logistic regression on sanitized text
    B9   logistic regression on embeddings
    B10  two-class kNN (mean top-k phishing sim - mean top-k legit sim)
    CC-R CyberCane retrieval score over a phishing-only index
         (0.65*top + 0.35*avg_top3, as in service._compute_ai_score)
    CC-F CyberCane full score: max(n, 0.7n + 0.3p), p from the Phase 1 verdict
  Primary metric: realized target FPR / budget, with Clopper-Pearson 95% CI.

Runs offline over cached embeddings (embed_cache_v2); no provider calls.

Usage:
  PYTHONPATH=api python -m app.evaluation.pilot_c1_shift --embed text-embedding-3-small
"""

import argparse
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import beta
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

from app.evaluation.embed_cache_v2 import CACHE, SPLITS, row_uid
from app.evaluation.label_policy import task_label
from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact

WS = Path(os.environ.get("CYBERCANE_WS", Path(__file__).resolve().parents[3] / "workspace"))
BUDGETS = (0.005, 0.01, 0.02)
K = 8
PHASE1_SIGNAL = {"phishing": 1.0, "needs_review": 0.6, "benign": 0.0}


# ============================================================================
# Data
# ============================================================================

def load(family: str, split: str, task: str, embed: str, seed: int = 42) -> pd.DataFrame:
    df = pd.read_csv(SPLITS / f"{family}_seed{seed}_{split}.csv")
    for c in ("subject", "body"):
        df[c] = df[c].fillna("").astype(str)
    if "orig_id" not in df.columns:
        df["orig_id"] = ""
    df["row_uid"] = [row_uid(r) for r in df.itertuples()]
    df = df.drop_duplicates("row_uid")
    df["y"] = [task_label(f, task) for f in df.fine]
    df = df[df.y.notna()].copy()
    df["y"] = df.y.astype(int)
    san = pd.read_csv(CACHE / f"sanitized_{family}.csv", keep_default_na=False)
    idx = pd.read_csv(CACHE / f"emb_{embed}_{family}.idx.csv")
    df = df.merge(san[["row_uid", "san_hash", "sanitized"]], on="row_uid", validate="one_to_one")
    df = df.merge(idx, on="san_hash", validate="many_to_one")
    vecs = np.load(CACHE / f"emb_{embed}_{family}.npy")
    df.attrs["X"] = vecs[df.idx.values.astype(int)]
    df["phase1"] = [
        score_email(sender=str(r.sender or ""), subject=r.subject, body=redact(r.body)[0],
                    url_flag=int(r.urls), allowed_brand_domains=[], enable_dns_checks=False).verdict
        for r in df.itertuples()
    ]
    return df.reset_index(drop=True)


# ============================================================================
# Scorers: fit on train, return continuous scores for any frame
# ============================================================================

def _topk_mean(sims: np.ndarray, k: int) -> np.ndarray:
    k = min(k, sims.shape[1])
    return np.sort(np.partition(sims, -k, axis=1)[:, -k:], axis=1)[:, ::-1]


def fit_scorers(train: pd.DataFrame):
    Xtr, ytr = train.attrs["X"], train.y.values
    tfidf = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=100_000, sublinear_tf=True)
    b3 = LogisticRegression(max_iter=3000, C=4).fit(tfidf.fit_transform(train.sanitized), ytr)
    b9 = LogisticRegression(max_iter=3000, C=1).fit(Xtr, ytr)
    pos, neg = Xtr[ytr == 1], Xtr[ytr == 0]

    def score(df: pd.DataFrame) -> dict:
        X = df.attrs["X"]
        sp = _topk_mean(X @ pos.T, K)
        sn = _topk_mean(X @ neg.T, K)
        top, avg3 = sp[:, 0], sp[:, :3].mean(axis=1)
        n = 0.65 * top + 0.35 * avg3                      # service._compute_ai_score neighbor signal
        p = df.phase1.map(PHASE1_SIGNAL).values
        full = np.clip(np.maximum(n, 0.7 * n + 0.3 * p), 0, 1)
        return {
            "B3_tfidf_lr": b3.decision_function(tfidf.transform(df.sanitized)),
            "B9_emb_lr": b9.decision_function(X),
            "B10_knn_2class": sp.mean(axis=1) - sn.mean(axis=1),
            "CC_retrieval": n,
            "CC_full": full,
            "_top": top, "_avg3": avg3,
        }
    return score


# ============================================================================
# Evaluation
# ============================================================================

def cp(k: int, n: int) -> tuple:
    lo = beta.ppf(0.025, k, n - k + 1) if k > 0 else 0.0
    hi = beta.ppf(0.975, k + 1, n - k) if k < n else 1.0
    return float(lo), float(hi)


def evaluate(setting: str, task: str, val: pd.DataFrame, test: pd.DataFrame, sv: dict, st: dict) -> list:
    rows = []
    yv, yt = val.y.values, test.y.values
    for m in (k for k in st if not k.startswith("_")):
        auroc = roc_auc_score(yt, st[m])
        for b in BUDGETS:
            neg = np.sort(sv[m][yv == 0])
            # smallest threshold whose validation FPR <= budget
            j = int(np.floor(len(neg) * (1 - b)))
            thr = neg[min(j, len(neg) - 1)]
            pred = st[m] > thr
            fp, nneg = int(pred[yt == 0].sum()), int((yt == 0).sum())
            tp, npos = int(pred[yt == 1].sum()), int((yt == 1).sum())
            lo, hi = cp(fp, nneg)
            rows.append(dict(setting=setting, task=task, method=m, budget=b, auroc=round(auroc, 4),
                             val_fpr=round(float((sv[m][yv == 0] > thr).mean()), 4),
                             test_fpr=round(fp / nneg, 4), fpr_ci_lo=round(lo, 4), fpr_ci_hi=round(hi, 4),
                             ratio=round((fp / nneg) / b, 2), recall=round(tp / npos, 4),
                             precision=round(tp / max(1, int(pred.sum())), 4), fp=fp, n_neg=nneg, n_pos=npos))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--embed", default="text-embedding-3-small")
    args = ap.parse_args()
    out = WS / "reports_v2" / f"c1_pilot_{args.embed}_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)

    results, preds = [], []
    for task in ("phish", "unwanted"):
        data = {(f, s): load(f, s, task, args.embed) for f in ("nazsa", "dataphish") for s in ("train", "val", "test")}
        for src, tgt in (("nazsa", "dataphish"), ("dataphish", "nazsa"), ("nazsa", "nazsa"), ("dataphish", "dataphish")):
            setting = f"{src}->{tgt}" if src != tgt else f"in-domain {src}"
            score = fit_scorers(data[(src, "train")])
            sv, st = score(data[(src, "val")]), score(data[(tgt, "test")])
            results += evaluate(setting, task, data[(src, "val")], data[(tgt, "test")], sv, st)
            p = data[(tgt, "test")][["row_uid", "y", "phase1", "source", "creator"]].copy()
            p.attrs = {}  # drop the cached embedding matrix before concatenation
            for m, v in st.items():
                p[m] = v
            p["setting"], p["task"] = setting, task
            preds.append(p)
            print(f"done {task} {setting}")

    res = pd.DataFrame(results)
    res.to_csv(out / "results.csv", index=False)
    pd.concat(preds).to_csv(out / "predictions.csv", index=False)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        protocol="Audit v2 (preregistered)", embed=args.embed, budgets=BUDGETS, k=K,
        commit=commit, dns_policy="off", split_seed=42,
        sanitize_manifest=json.loads((CACHE / "sanitize_manifest.json").read_text())), indent=2))
    print("wrote", out)


if __name__ == "__main__":
    main()
