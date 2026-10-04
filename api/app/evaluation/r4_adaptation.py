"""
R4: adaptation without retraining (claim C2).

Protocol and success criteria were fixed before the run (R4, preregistration table in the paper).
k DataPhish-train phishing examples (none near-duplicate to the target test) are
added to CyberCane's phishing index, or to the training set of B3/B9, which are
retrained. Thresholds always come from source validation. CPU only; $0.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.r4_adaptation
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.pilot_c1_shift import BUDGETS, WS, fit_scorers
from app.evaluation.r2_benign_shift import BENIGN, benign, dataphish, decontaminate, nazario
from app.evaluation.r5_style_shift import concat, subset
from app.evaluation.replicate_c1 import thresholds
from app.evaluation.replicate_c1_decontam import XDUP, cross_max_sim

KS = (0, 5, 10, 25, 50)
DRAWS = 3
METHODS = ("CC_full", "B3_tfidf_lr", "B9_emb_lr")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"r4_adaptation_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rows = []

    for seed in args.seeds:
        dp_test = dataphish("test", seed)
        dp_train = dataphish("train", seed)
        cand_all = subset(dp_train, dp_train.y == 1)
        for pair in BENIGN:
            src_tr = concat(nazario("train", seed), benign(pair, "train", seed))
            src_va = concat(nazario("val", seed), benign(pair, "val", seed))
            tgt, _ = decontaminate(dp_test, src_tr)
            # Adaptation candidates must not near-duplicate any target test row.
            cand = subset(cand_all, cross_max_sim(cand_all, tgt) < XDUP)
            yv, yt = src_va.y.values, tgt.y.values
            for k in KS:
                for draw in range(DRAWS if k else 1):
                    rng = np.random.default_rng(1000 * seed + 10 * k + draw)
                    if k:
                        pick = np.zeros(len(cand), bool)
                        pick[rng.choice(len(cand), size=k, replace=False)] = True
                        train = concat(src_tr, subset(cand, pick))
                    else:
                        train = src_tr
                    score = fit_scorers(train)
                    sv, st = score(src_va), score(tgt)
                    for m in METHODS:
                        for b in BUDGETS:
                            for rule, thr in thresholds(sv[m][yv == 0], b).items():
                                if rule == "zero_fp" and b != BUDGETS[0]:
                                    continue
                                pred = st[m] > thr
                                rows.append(dict(seed=seed, pair=pair, k=k, draw=draw, method=m, rule=rule,
                                                 budget=b if rule != "zero_fp" else None,
                                                 test_fpr=pred[yt == 0].mean(), recall=pred[yt == 1].mean(),
                                                 n_candidates=len(cand)))
            print(f"seed {seed} {pair}: done ({len(cand)} candidates)", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)
    g = res[(res.rule == "budget") & (res.budget == 0.01)]
    verdict = []
    for pair, h in g.groupby("pair"):
        m = h.groupby(["method", "k"])[["test_fpr", "recall"]].mean()
        cc0, cc25 = m.loc[("CC_full", 0)], m.loc[("CC_full", 25)]
        base25 = min(m.loc[("B3_tfidf_lr", 25), "test_fpr"], m.loc[("B9_emb_lr", 25), "test_fpr"])
        verdict.append(dict(pair=pair, cc_rec0=cc0.recall, cc_rec25=cc25.recall, cc_fpr0=cc0.test_fpr,
                            cc_fpr25=cc25.test_fpr, best_baseline_fpr25=base25,
                            meets=bool(cc25.recall >= cc0.recall + 0.05 and cc25.test_fpr <= cc0.test_fpr + 0.01
                                       and cc25.test_fpr < base25)))
    crit = dict(pairs=verdict, claimed=sum(v["meets"] for v in verdict) >= 2)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="R4 preregistered adaptation without retraining (C2)", seeds=args.seeds, ks=KS, draws=DRAWS,
        xdup=XDUP, commit=commit, criterion=crit), indent=2, default=float))
    print("CRITERION", json.dumps(crit, default=float))
    print("wrote", out)


if __name__ == "__main__":
    main()
