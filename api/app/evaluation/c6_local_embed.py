"""
C6: fully local embeddings.

Protocol and success criteria were fixed before the run (C6, preregistration table in the paper).
Reruns the R2 forward benign shift (SpamAssassin / CEAS / Ling-Spam ->
decontaminated DataPhish 2025 test) with the cloud embedder and with a local
open embedder in the same driver, so the pipeline is identical. Scorers,
weights, K and thresholds are unchanged. Writes to reports_v2/c6_local_embed_*
(a distinct prefix, so table generators never mistake it for R2).
CPU only; no provider calls (embeddings come from cache_v2).

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.c6_local_embed
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from app.evaluation import r2_benign_shift as r2
from app.evaluation.pilot_c1_shift import BUDGETS, WS
from app.evaluation.r5_style_shift import concat
from app.evaluation.replicate_c1 import thresholds

EMBEDDERS = ("text-embedding-3-small", "bge-base-en-v1.5")
LOCAL = "bge-base-en-v1.5"
METHODS = ("B3_tfidf_lr", "B9_emb_lr", "B10_knn_2class", "B11_tfidf_phishonly_knn", "CC_full")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"c6_local_embed_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    for emb in EMBEDDERS:
        r2.EMBED = emb  # loaders read the module global at call time
        for seed in args.seeds:
            dp_test = r2.dataphish("test", seed)
            for pair in r2.BENIGN:
                src_tr = concat(r2.nazario("train", seed), r2.benign(pair, "train", seed))
                src_va = concat(r2.nazario("val", seed), r2.benign(pair, "val", seed))
                tgt, _ = r2.decontaminate(dp_test, src_tr)
                sv, st = r2.all_scores(src_tr, [src_va, tgt])
                yv, yt = src_va.y.values, tgt.y.values
                for m in METHODS:
                    row = dict(embedder=emb, seed=seed, pair=pair, method=m,
                               auroc=roc_auc_score(yt, st[m]), pauc2=roc_auc_score(yt, st[m], max_fpr=0.02))
                    for b in BUDGETS:
                        pred = st[m] > thresholds(sv[m][yv == 0], b)["budget"]
                        row[f"fpr_{b}"] = float(pred[yt == 0].mean())
                        row[f"recall_{b}"] = float(pred[yt == 1].mean())
                    rows.append(row)
                print(f"{emb} seed {seed} {pair}: done", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)

    loc = res[res.embedder == LOCAL]
    c6a, c6b, c6c = {}, {}, {}
    for pair in r2.BENIGN:
        piv = loc[loc.pair == pair].pivot_table(index="seed", columns="method", values="fpr_0.01")
        c6a[pair] = int((piv.CC_full < piv[["B3_tfidf_lr", "B9_emb_lr"]].min(axis=1)).sum())
        pa = loc[loc.pair == pair].groupby("method").pauc2.mean()
        c6b[pair] = pa.idxmax()
        cc = res[(res.pair == pair) & (res.method == "CC_full")].groupby("embedder")[["pauc2", "recall_0.01"]].mean()
        c6c[pair] = dict(dpauc=float(cc.loc[LOCAL, "pauc2"] - cc.loc[EMBEDDERS[0], "pauc2"]),
                         drecall=float(cc.loc[LOCAL, "recall_0.01"] - cc.loc[EMBEDDERS[0], "recall_0.01"]))
    verdict = dict(
        C6a_seeds=c6a, C6a=sum(v >= 4 for v in c6a.values()) >= 2,
        C6b_best_pauc2=c6b, C6b=sum(v == "CC_full" for v in c6b.values()) >= 2,
        C6c_deltas=c6c, C6c=all(abs(d["dpauc"]) <= 0.05 and abs(d["drecall"]) <= 0.10 for d in c6c.values()))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="C6 preregistered fully local embeddings", seeds=args.seeds, budgets=BUDGETS,
        embedders=EMBEDDERS, methods=METHODS, commit=commit, criterion=verdict), indent=2))
    summ = res.groupby(["embedder", "pair", "method"])[["fpr_0.01", "recall_0.01", "pauc2", "auroc"]].mean()
    print(summ.round(4).to_string())
    print("CRITERION", json.dumps(verdict))
    print("wrote", out)


if __name__ == "__main__":
    main()
