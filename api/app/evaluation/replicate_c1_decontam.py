"""
R1b: C1 replication with cross-corpus decontamination.

Audit finding: DataPhish includes human phishing that near-duplicates the
Nazario corpus (195/900 seed-42 test phishing rows at char-TF-IDF cosine
>= 0.9 to Nazario/SpamAssassin train). This inflates recall in the shift
setting and favors retrieval. This script:

  1. Drops every target-test group (DataPhish rewrite family) that has any
     member with cosine >= XDUP to the source TRAIN split, per seed.
  2. Reports FPR confidence intervals by cluster bootstrap over groups
     (rewrite families are correlated), alongside Clopper-Pearson.
  3. Adds B11: phishing-only kNN over TF-IDF with CyberCane's score formula,
     to test whether the effect needs neural embeddings or only a
     positive-only retrieval rule.

CPU only; no provider calls. Shift setting only (Nazario/SpamAssassin -> DataPhish).

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.replicate_c1_decontam
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

from app.evaluation.build_splits_v2 import normalize
from app.evaluation.pilot_c1_shift import BUDGETS, WS, cp, fit_scorers, load
from app.evaluation.replicate_c1 import thresholds

XDUP = 0.80
N_BOOT = 1000


def cross_max_sim(test: pd.DataFrame, train: pd.DataFrame) -> np.ndarray:
    a = [normalize(s, b) for s, b in zip(test.subject, test.body)]
    b = [normalize(s, b) for s, b in zip(train.subject, train.body)]
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2,
                          max_features=200_000, sublinear_tf=True).fit(a + b)
    A, B = vec.transform(a), vec.transform(b)
    out = np.zeros(A.shape[0])
    for s in range(0, A.shape[0], 500):
        out[s:s + 500] = (A[s:s + 500] @ B.T).max(axis=1).toarray().ravel()
    return out


def b11_scores(train: pd.DataFrame, frames: list) -> list:
    """Phishing-only kNN over word TF-IDF, CyberCane score formula (0.65 top + 0.35 avg3)."""
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=100_000, sublinear_tf=True)
    vec.fit(train.sanitized)
    P = vec.transform(train.sanitized[train.y.values == 1])
    res = []
    for df in frames:
        S = (vec.transform(df.sanitized) @ P.T).toarray()
        top3 = -np.sort(-S, axis=1)[:, :3]
        res.append(0.65 * top3[:, 0] + 0.35 * top3.mean(axis=1))
    return res


def cluster_boot_fpr(pred_neg: np.ndarray, groups: np.ndarray, rng) -> tuple:
    ug, inv = np.unique(groups, return_inverse=True)
    fp_g = np.bincount(inv, weights=pred_neg.astype(float))
    n_g = np.bincount(inv).astype(float)
    idx = rng.integers(0, len(ug), size=(N_BOOT, len(ug)))
    boots = fp_g[idx].sum(axis=1) / n_g[idx].sum(axis=1)
    return float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    ap.add_argument("--embed", default="text-embedding-3-small")
    args = ap.parse_args()
    out = WS / "reports_v2" / f"c1_decontam_{args.embed}_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(0)

    rows, contam = [], []
    for seed in args.seeds:
        for task in ("phish", "unwanted"):
            train = load("nazsa", "train", task, args.embed, seed=seed)
            val = load("nazsa", "val", task, args.embed, seed=seed)
            test_all = load("dataphish", "test", task, args.embed, seed=seed)  # carries `group`
            msim = cross_max_sim(test_all, train)
            bad_groups = set(test_all.group[msim >= XDUP])
            keep = ~test_all.group.isin(bad_groups).values
            contam.append(dict(seed=seed, task=task, test_rows=len(test_all), dropped_rows=int((~keep).sum()),
                               dropped_groups=len(bad_groups),
                               dropped_pos=int(((~keep) & (test_all.y.values == 1)).sum()),
                               dropped_neg=int(((~keep) & (test_all.y.values == 0)).sum())))

            score = fit_scorers(train)
            sv, st_all = score(val), score(test_all)
            sv["B11_tfidf_phishonly_knn"], st_all["B11_tfidf_phishonly_knn"] = b11_scores(train, [val, test_all])

            for subset, mask in (("all", np.ones(len(test_all), bool)), ("decontam", keep)):
                yt = test_all.y.values[mask]
                grp = test_all.group.values[mask]
                nneg, npos = int((yt == 0).sum()), int((yt == 1).sum())
                for m in (k for k in st_all if not k.startswith("_")):
                    s_t = st_all[m][mask]
                    for b in BUDGETS:
                        for rule, thr in thresholds(sv[m][val.y.values == 0], b).items():
                            if rule == "zero_fp" and b != BUDGETS[0]:
                                continue
                            pred = s_t > thr
                            fp, tp = int(pred[yt == 0].sum()), int(pred[yt == 1].sum())
                            lo, hi = cp(fp, nneg)
                            blo, bhi = cluster_boot_fpr(pred[yt == 0], grp[yt == 0], rng)
                            rows.append(dict(seed=seed, task=task, subset=subset, method=m, rule=rule,
                                             budget=b if rule != "zero_fp" else None,
                                             test_fpr=fp / nneg, cp_lo=lo, cp_hi=hi, boot_lo=blo, boot_hi=bhi,
                                             recall=tp / npos, fp=fp, n_neg=nneg, n_pos=npos))
            print(f"seed {seed} {task}: dropped {contam[-1]['dropped_rows']} rows "
                  f"({contam[-1]['dropped_pos']} pos, {contam[-1]['dropped_neg']} neg)", flush=True)

    pd.DataFrame(rows).to_csv(out / "results.csv", index=False)
    pd.DataFrame(contam).to_csv(out / "contamination.csv", index=False)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="R1b: C1 with cross-corpus decontamination, cluster-bootstrap CIs, B11 positive-only TF-IDF kNN",
        xdup=XDUP, n_boot=N_BOOT, seeds=args.seeds, embed=args.embed, budgets=BUDGETS,
        commit=commit, dns_policy="off"), indent=2))
    print("wrote", out)


if __name__ == "__main__":
    main()
