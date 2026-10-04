"""
T1: calibration-transfer curves (descriptive).

For each method, the threshold for budget b is the (1-b) quantile of its scores
on source-validation legitimate mail (the R2 rule). The transfer curve maps the
nominal budget b to the realized FPR on decontaminated DataPhish legitimate mail.
Perfect transfer is the diagonal. Evaluated on a dense grid of budgets
(0.1%-30%) for every seed and source, so the 0.5/1/2% points coincide with R2.
Same scorers, splits, and decontamination as R2. CPU only; no provider calls.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.t1_transfer_curves
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.pilot_c1_shift import WS
from app.evaluation.r2_benign_shift import BENIGN, all_scores, benign, dataphish, decontaminate, nazario
from app.evaluation.r5_style_shift import concat
from app.evaluation.replicate_c1 import thresholds

METHODS = ("B3_tfidf_lr", "B9_emb_lr", "B10_knn_2class", "CC_full")
GRID = np.unique(np.round(np.geomspace(0.001, 0.30, 40), 6).tolist() + [0.005, 0.01, 0.02])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"t1_transfer_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for seed in args.seeds:
        dp_test = dataphish("test", seed)
        for pair in BENIGN:
            src_tr = concat(nazario("train", seed), benign(pair, "train", seed))
            src_va = concat(nazario("val", seed), benign(pair, "val", seed))
            tgt, _ = decontaminate(dp_test, src_tr)
            sv, st = all_scores(src_tr, [src_va, tgt])
            yv, yt = src_va.y.values, tgt.y.values
            for m in METHODS:
                neg_v = sv[m][yv == 0]
                for b in GRID:
                    thr = thresholds(neg_v, float(b))["budget"]   # exactly the R2 rule
                    pred = st[m] > thr
                    rows.append(dict(seed=seed, pair=pair, method=m, budget=float(b),
                                     source_fpr=float((neg_v > thr).mean()),
                                     test_fpr=float(pred[yt == 0].mean()), recall=float(pred[yt == 1].mean()),
                                     n_val_neg=int(len(neg_v)), n_test_neg=int((yt == 0).sum())))
            print(f"seed {seed} {pair}: done", flush=True)
    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="T1 descriptive calibration-transfer curves (figure data)", seeds=args.seeds,
        methods=METHODS, grid=GRID.tolist(), commit=commit), indent=2))
    g = res[res.budget.isin([0.005, 0.01, 0.02])].groupby(["pair", "method", "budget"]).test_fpr.mean().unstack()
    print((g * 100).round(1).to_string())
    print("wrote", out)


if __name__ == "__main__":
    main()
