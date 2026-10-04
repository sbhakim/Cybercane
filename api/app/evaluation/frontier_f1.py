"""
F1: matched-FPR frontier.

Protocol and success criteria were fixed before the run (F1, preregistration table in the paper).
Oracle, descriptive analysis: recall at fixed realized FPR on the deployment
mail, with thresholds chosen on target labels (not a deployable rule).
Recall at FPR f is the largest TPR among thresholds whose target FPR <= f
(step function from roc_curve; ties are not interpolated).

Forward benign shift (SpamAssassin / CEAS / Ling-Spam -> decontaminated
DataPhish 2025), phish task, 5 seeds. Scores come from the unchanged scorers
and the cached zero-shot LLM responses; per-example scores are saved.
CPU only; no provider calls.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.frontier_f1
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve

from app.evaluation.llm_zero_shot import CACHE_FILE as B12_CACHE
from app.evaluation.pilot_c1_shift import WS
from app.evaluation.r2_benign_shift import BENIGN, all_scores, benign, dataphish, decontaminate, nazario
from app.evaluation.r5_style_shift import concat

FPR_LEVELS = (0.005, 0.01, 0.02, 0.05, 0.10)
METHODS = ("B3_tfidf_lr", "B9_emb_lr", "B10_knn_2class", "B11_tfidf_phishonly_knn", "CC_full", "B12_llm")


def recall_at_fpr(y: np.ndarray, s: np.ndarray, level: float) -> float:
    fpr, tpr, _ = roc_curve(y, s)
    ok = fpr <= level + 1e-12
    return float(tpr[ok].max()) if ok.any() else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"f1_frontier_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)

    b12 = pd.DataFrame([json.loads(l) for l in B12_CACHE.read_text().splitlines()])
    b12 = b12[b12.status == "ok"].drop_duplicates("row_uid", keep="last").set_index("row_uid").prob

    rows, scores = [], []
    for seed in args.seeds:
        dp_test = dataphish("test", seed)
        for pair in BENIGN:
            src_tr = concat(nazario("train", seed), benign(pair, "train", seed))
            tgt, _ = decontaminate(dp_test, src_tr)
            st = all_scores(src_tr, [tgt])[0]
            st["B12_llm"] = b12.reindex(tgt.row_uid).values.astype(float)
            assert not np.isnan(st["B12_llm"]).any(), f"missing B12 scores ({pair}, seed {seed})"
            y = tgt.y.values
            for m in METHODS:
                s = st[m]
                rec = {f"recall_at_{lv}": recall_at_fpr(y, s, lv) for lv in FPR_LEVELS}
                rows.append(dict(seed=seed, pair=pair, method=m, auroc=roc_auc_score(y, s),
                                 pauc2=roc_auc_score(y, s, max_fpr=0.02), pauc10=roc_auc_score(y, s, max_fpr=0.10),
                                 n_neg=int((y == 0).sum()), n_pos=int((y == 1).sum()), **rec))
            sc = tgt[["row_uid", "y", "creator"]].copy()
            sc.attrs = {}
            for m in METHODS:
                sc[m] = st[m]
            sc["seed"], sc["pair"] = seed, pair
            scores.append(sc)
            print(f"seed {seed} {pair}: done", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)
    pd.concat(scores, ignore_index=True).to_csv(out / "scores.csv", index=False)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="F1 preregistered matched-FPR frontier (oracle, descriptive)", seeds=args.seeds,
        fpr_levels=FPR_LEVELS, methods=METHODS, commit=commit), indent=2))
    print("wrote", out)


if __name__ == "__main__":
    main()
