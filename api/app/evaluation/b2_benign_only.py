"""
B2: legitimate-mail-only shift.

Protocol and success criteria were fixed before the run (B2, preregistration table in the paper).
Phishing is fixed (Nazario, group-disjoint splits); only the legitimate mail
changes between calibration source A and deployment source B, over all ordered
pairs of {SpamAssassin, CEAS, Ling-Spam}. Target = Nazario test phishing +
B test legitimate, decontaminated against the training set.
Rules: source-validation thresholds (primary) and the R6 label-free mixture on
an unlabeled deployment pool (B train legitimate + Nazario val phishing).
CPU only; no provider calls.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.b2_benign_only
"""

import argparse
import itertools
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.pilot_c1_shift import BUDGETS, WS
from app.evaluation.r2_benign_shift import BENIGN, all_scores, benign, decontaminate, nazario
from app.evaluation.r5_style_shift import concat
from app.evaluation.r6_recalibration import l2_threshold
from app.evaluation.replicate_c1 import thresholds

METHODS = ("B3_tfidf_lr", "B9_emb_lr", "B10_knn_2class", "B11_tfidf_phishonly_knn", "CC_full")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"b2_benign_only_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rows, contam = [], []

    for seed in args.seeds:
        naz = {s: nazario(s, seed) for s in ("train", "val", "test")}
        for a, b in itertools.permutations(BENIGN, 2):
            src_tr = concat(naz["train"], benign(a, "train", seed))
            src_va = concat(naz["val"], benign(a, "val", seed))
            tgt, dropped = decontaminate(concat(naz["test"], benign(b, "test", seed)), src_tr)
            pool = concat(benign(b, "train", seed), naz["val"])
            sv, sp, st = all_scores(src_tr, [src_va, pool, tgt])
            yv, yt = src_va.y.values, tgt.y.values
            contam.append(dict(seed=seed, source=a, target=b, dropped=dropped, kept=len(tgt),
                               n_neg=int((yt == 0).sum()), n_pos=int((yt == 1).sum())))
            for m in METHODS:
                for bud in BUDGETS:
                    for rule, thr in (("source", thresholds(sv[m][yv == 0], bud)["budget"]),
                                      ("L2_mixture", l2_threshold(sp[m], bud))):
                        pred = st[m] > thr
                        rows.append(dict(seed=seed, source=a, target=b, method=m, rule=rule, budget=bud,
                                         test_fpr=float(pred[yt == 0].mean()), recall=float(pred[yt == 1].mean())))
            print(f"seed {seed} {a}->{b}: done (dropped {dropped})", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)
    pd.DataFrame(contam).to_csv(out / "contamination.csv", index=False)

    g = res[(res.rule == "source") & (res.budget == 0.01)]
    pairs = []
    for (a, b), h in g.groupby(["source", "target"]):
        means = h.groupby("method").test_fpr.mean()
        overrun = bool(min(means["B3_tfidf_lr"], means["B9_emb_lr"]) > 0.02)
        piv = h.pivot_table(index="seed", columns="method", values="test_fpr")
        adv_seeds = int((piv.CC_full < piv[["B3_tfidf_lr", "B9_emb_lr"]].min(axis=1)).sum())
        pairs.append(dict(source=a, target=b, overrun_present=overrun, cc_below_both_seeds=adv_seeds,
                          better_baseline_fpr=float(min(means["B3_tfidf_lr"], means["B9_emb_lr"])),
                          cc_fpr=float(means["CC_full"])))
    n_over = sum(p["overrun_present"] for p in pairs)
    adv_ok = all(p["cc_below_both_seeds"] >= 4 for p in pairs if p["overrun_present"])
    verdict = dict(pairs=pairs, pairs_with_overrun=n_over, generalizes=bool(n_over >= 2 and adv_ok))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="B2 preregistered legitimate-mail-only shift", seeds=args.seeds, budgets=BUDGETS,
        methods=METHODS, commit=commit, criterion=verdict), indent=2))
    print("CRITERION", json.dumps(verdict))
    print("wrote", out)


if __name__ == "__main__":
    main()
