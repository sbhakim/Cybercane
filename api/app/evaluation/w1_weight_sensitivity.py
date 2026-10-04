"""
W1: sensitivity of the main result to CyberCane's hand-set score weights.

Protocol and success criteria were fixed before the run (W1, preregistration table in the paper).
Grid over the neighbor weight w (n = w*s1 + (1-w)*mean(s1..s3)) and the Phase 1
blend alpha (r = max(n, (1-alpha)*n + alpha*p(l1))); defaults w=0.65, alpha=0.3.
Robustness analysis only: no configuration is selected, the defaults stay.
R2 forward shift, source-validation thresholds, 1% budget (all budgets saved).
CPU only; no provider calls.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.w1_weight_sensitivity
"""

import argparse
import itertools
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from app.evaluation.pilot_c1_shift import BUDGETS, PHASE1_SIGNAL, WS, fit_scorers
from app.evaluation.r2_benign_shift import BENIGN, benign, dataphish, decontaminate, nazario
from app.evaluation.r5_style_shift import concat
from app.evaluation.replicate_c1 import thresholds

W_GRID = (0.4, 0.5, 0.65, 0.8, 1.0)
A_GRID = (0.0, 0.15, 0.3, 0.45)
DEFAULT = (0.65, 0.3)


def cc_score(raw: dict, p: np.ndarray, w: float, a: float) -> np.ndarray:
    n = w * raw["_top"] + (1 - w) * raw["_avg3"]
    return np.clip(np.maximum(n, (1 - a) * n + a * p), 0, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"w1_weights_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    for seed in args.seeds:
        dp_test = dataphish("test", seed)
        for pair in BENIGN:
            src_tr = concat(nazario("train", seed), benign(pair, "train", seed))
            src_va = concat(nazario("val", seed), benign(pair, "val", seed))
            tgt, _ = decontaminate(dp_test, src_tr)
            score = fit_scorers(src_tr)
            rv, rt = score(src_va), score(tgt)
            pv = src_va.phase1.map(PHASE1_SIGNAL).values
            pt = tgt.phase1.map(PHASE1_SIGNAL).values
            yv, yt = src_va.y.values, tgt.y.values
            # sanity: the default configuration reproduces the CC_full scorer exactly
            assert np.allclose(cc_score(rt, pt, *DEFAULT), rt["CC_full"]), "default grid point != CC_full"
            base = {}
            for m in ("B3_tfidf_lr", "B9_emb_lr"):
                for b in BUDGETS:
                    pred = rt[m] > thresholds(rv[m][yv == 0], b)["budget"]
                    base[(m, b)] = float(pred[yt == 0].mean())
            for w, a in itertools.product(W_GRID, A_GRID):
                sv, st = cc_score(rv, pv, w, a), cc_score(rt, pt, w, a)
                row = dict(seed=seed, pair=pair, w=w, alpha=a, pauc2=roc_auc_score(yt, st, max_fpr=0.02))
                for b in BUDGETS:
                    pred = st > thresholds(sv[yv == 0], b)["budget"]
                    row[f"fpr_{b}"] = float(pred[yt == 0].mean())
                    row[f"recall_{b}"] = float(pred[yt == 1].mean())
                    row[f"base_min_fpr_{b}"] = min(base[("B3_tfidf_lr", b)], base[("B9_emb_lr", b)])
                rows.append(row)
            print(f"seed {seed} {pair}: done", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)

    per_cfg = {}
    for (w, a), h in res.groupby(["w", "alpha"]):
        wins = {p: int((g["fpr_0.01"] < g["base_min_fpr_0.01"]).sum()) for p, g in h.groupby("pair")}
        per_cfg[f"w={w},alpha={a}"] = dict(seeds_below_both=wins, c1=sum(v >= 4 for v in wins.values()) >= 2)
    verdict = dict(configs=per_cfg, n_configs=len(per_cfg), n_c1=sum(v["c1"] for v in per_cfg.values()),
                   robust=all(v["c1"] for v in per_cfg.values()))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="W1 preregistered weight sensitivity (robustness, no selection)", seeds=args.seeds,
        w_grid=W_GRID, alpha_grid=A_GRID, default=DEFAULT, budgets=BUDGETS, commit=commit, criterion=verdict), indent=2))
    summ = res.groupby(["pair", "w", "alpha"])[["fpr_0.01", "recall_0.01", "pauc2", "base_min_fpr_0.01"]].mean()
    print(summ.round(4).to_string())
    print("CRITERION", json.dumps(dict(n_configs=verdict["n_configs"], n_c1=verdict["n_c1"], robust=verdict["robust"])))
    print("wrote", out)


if __name__ == "__main__":
    main()
