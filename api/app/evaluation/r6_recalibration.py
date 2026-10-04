"""
R6: label-free recalibration threat test.

Protocol and success criteria were fixed before the run (R6, preregistration table in the paper).
Can unlabeled deployment mail recalibrate trained baselines' thresholds?
  L1  oracle-prevalence quantile on unlabeled pool scores (generous upper bound)
  L2  two-component Gaussian mixture on unlabeled pool scores (label-free)
  source  thresholds from source-validation legitimate mail (R2 rule)
Unlabeled pool: DataPhish train split (labels discarded except to compute the
oracle prevalence for L1). Target: decontaminated DataPhish test.
CPU only; no provider calls.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.r6_recalibration
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import norm
from sklearn.mixture import GaussianMixture

from app.evaluation.pilot_c1_shift import BUDGETS, WS
from app.evaluation.r2_benign_shift import BENIGN, all_scores, benign, dataphish, decontaminate, nazario
from app.evaluation.r5_style_shift import concat
from app.evaluation.replicate_c1 import thresholds

METHODS = ("B3_tfidf_lr", "B9_emb_lr", "B10_knn_2class", "CC_full")


def l1_threshold(pool_scores: np.ndarray, prevalence: float, b: float) -> float:
    flagged = min(1.0, prevalence + b * (1 - prevalence))
    return float(np.quantile(pool_scores, 1 - flagged))


def l2_threshold(pool_scores: np.ndarray, b: float) -> float:
    gm = GaussianMixture(n_components=2, random_state=0).fit(pool_scores.reshape(-1, 1))
    k = int(np.argmin(gm.means_.ravel()))
    mu, sd = float(gm.means_.ravel()[k]), float(np.sqrt(gm.covariances_.ravel()[k]))
    return mu + norm.ppf(1 - b) * sd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"r6_recalibration_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rows = []

    for seed in args.seeds:
        dp_test = dataphish("test", seed)
        pool = dataphish("train", seed)
        prevalence = float(pool.y.mean())
        for pair in BENIGN:
            src_tr = concat(nazario("train", seed), benign(pair, "train", seed))
            src_va = concat(nazario("val", seed), benign(pair, "val", seed))
            tgt, _ = decontaminate(dp_test, src_tr)
            sv, sp, st = all_scores(src_tr, [src_va, pool, tgt])
            yv, yt = src_va.y.values, tgt.y.values
            for m in METHODS:
                for b in BUDGETS:
                    rules = {
                        "source": thresholds(sv[m][yv == 0], b)["budget"],
                        "L1_oracle_prevalence": l1_threshold(sp[m], prevalence, b),
                        "L2_mixture": l2_threshold(sp[m], b),
                    }
                    for rule, thr in rules.items():
                        pred = st[m] > thr
                        rows.append(dict(seed=seed, pair=pair, method=m, rule=rule, budget=b,
                                         test_fpr=float(pred[yt == 0].mean()), recall=float(pred[yt == 1].mean()),
                                         threshold=float(thr), pool_prevalence=prevalence))
            print(f"seed {seed} {pair}: done", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)

    # Preregistered criterion: L2, 1% budget, CC below both B3 and B9 in >=4/5 seeds, >=2/3 sources
    g = res[(res.rule == "L2_mixture") & (res.budget == 0.01)]
    per_pair = {}
    for pair, h in g.groupby("pair"):
        piv = h.pivot_table(index="seed", columns="method", values="test_fpr")
        per_pair[pair] = int((piv.CC_full < piv[["B3_tfidf_lr", "B9_emb_lr"]].min(axis=1)).sum())
    verdict = dict(seeds_cc_below_both=per_pair,
                   robust=sum(v >= 4 for v in per_pair.values()) >= 2)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="R6 preregistered label-free recalibration threat test", seeds=args.seeds, budgets=BUDGETS,
        methods=METHODS, commit=commit, criterion=verdict), indent=2))
    print("CRITERION", json.dumps(verdict))
    print("wrote", out)


if __name__ == "__main__":
    main()
