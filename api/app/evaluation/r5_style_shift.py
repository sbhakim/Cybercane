"""
R5: realistic attack-style shift for claim C1.

Protocol and success criteria were fixed before the run (R5, preregistration table in the paper).
  Source: human-written DataPhish rows of the train+val groups (phish task).
  Target: LLM-written rows of the test groups. Control: human-written test rows.
  Thresholds: quantiles of 5-fold group-wise out-of-fold source negative scores.
  CIs: cluster bootstrap over rewrite-family groups.

CPU only; no provider calls.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.r5_style_shift
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold

from app.evaluation.pilot_c1_shift import BUDGETS, WS, fit_scorers, load
from app.evaluation.replicate_c1 import thresholds
from app.evaluation.replicate_c1_decontam import b11_scores, cluster_boot_fpr

EMBED = "text-embedding-3-small"


def subset(df: pd.DataFrame, mask) -> pd.DataFrame:
    mask = np.asarray(mask, bool)
    out = df[mask].reset_index(drop=True)
    out.attrs = {"X": df.attrs["X"][mask]}
    return out


def concat(a: pd.DataFrame, b: pd.DataFrame) -> pd.DataFrame:
    X = np.vstack([a.attrs["X"], b.attrs["X"]])
    a2, b2 = a.copy(), b.copy()
    a2.attrs, b2.attrs = {}, {}  # pandas compares attrs on concat; keep the matrix out of it
    out = pd.concat([a2, b2], ignore_index=True)
    out.attrs = {"X": X}
    return out


def all_scores(train: pd.DataFrame, frames: list) -> list:
    score = fit_scorers(train)
    res = [{k: v for k, v in score(f).items() if not k.startswith("_")} for f in frames]
    for r, b in zip(res, b11_scores(train, frames)):
        r["B11_tfidf_phishonly_knn"] = b
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"r5_style_shift_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(0)
    rows, sizes = [], []

    for seed in args.seeds:
        tr, va, te = (load("dataphish", s, "phish", EMBED, seed=seed) for s in ("train", "val", "test"))
        src_all = concat(tr, va)
        src = subset(src_all, src_all.creator == "Human")
        targets = {"human->LLM": subset(te, te.creator != "Human"),
                   "human->human (control)": subset(te, te.creator == "Human")}

        # Out-of-fold source scores for threshold selection
        oof = None
        for k, (fit_idx, held_idx) in enumerate(GroupKFold(n_splits=5).split(src, groups=src.group)):
            fit_mask = np.zeros(len(src), bool)
            fit_mask[fit_idx] = True
            s_held = all_scores(subset(src, fit_mask), [subset(src, ~fit_mask)])[0]
            if oof is None:
                oof = {m: np.zeros(len(src)) for m in s_held}
            for m, v in s_held.items():
                oof[m][~fit_mask] = v
        neg_oof = {m: v[src.y.values == 0] for m, v in oof.items()}

        final = all_scores(src, list(targets.values()))
        for (setting, tgt), st in zip(targets.items(), final):
            yt, grp = tgt.y.values, tgt.group.values
            nneg, npos = int((yt == 0).sum()), int((yt == 1).sum())
            sizes.append(dict(seed=seed, setting=setting, source_rows=len(src),
                              source_neg=int((src.y == 0).sum()), test_neg=nneg, test_pos=npos))
            for m, s_t in st.items():
                for b in BUDGETS:
                    for rule, thr in thresholds(neg_oof[m], b).items():
                        if rule == "zero_fp" and b != BUDGETS[0]:
                            continue
                        pred = s_t > thr
                        fp, tp = int(pred[yt == 0].sum()), int(pred[yt == 1].sum())
                        blo, bhi = cluster_boot_fpr(pred[yt == 0], grp[yt == 0], rng)
                        rows.append(dict(seed=seed, setting=setting, method=m, rule=rule,
                                         budget=b if rule != "zero_fp" else None,
                                         test_fpr=fp / nneg, boot_lo=blo, boot_hi=bhi,
                                         recall=tp / npos, fp=fp, n_neg=nneg, n_pos=npos))
        print(f"seed {seed}: source {len(src)} rows ({int((src.y == 0).sum())} neg)", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)
    pd.DataFrame(sizes).to_csv(out / "sizes.csv", index=False)

    # Preregistered criterion (human->LLM, phish, rule=budget)
    g = res[(res.setting == "human->LLM") & (res.rule == "budget")]
    seed_ok = []
    for seed, h in g.groupby("seed"):
        h = h.set_index(["method", "budget"]).test_fpr
        wins = sum(h[("CC_full", b)] < min(h[("B3_tfidf_lr", b)], h[("B9_emb_lr", b)]) for b in BUDGETS)
        seed_ok.append(wins >= 2)
    one = g[g.budget == 0.01].groupby("method")[["test_fpr", "boot_lo", "boot_hi"]].mean()
    better = min(("B3_tfidf_lr", "B9_emb_lr"), key=lambda m: one.loc[m, "test_fpr"])
    ci_sep = one.loc["CC_full", "boot_hi"] < one.loc[better, "boot_lo"]
    verdict = dict(seeds_meeting=int(sum(seed_ok)), n_seeds=len(seed_ok), ci_separated_at_1pct=bool(ci_sep),
                   better_baseline=better, met=bool(sum(seed_ok) >= 4 and ci_sep))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="R5 preregistered realistic attack-style shift", seeds=args.seeds, embed=EMBED,
        budgets=BUDGETS, threshold_source="5-fold GroupKFold OOF on source", commit=commit,
        criterion=verdict), indent=2))
    print("CRITERION", json.dumps(verdict))
    print("wrote", out)


if __name__ == "__main__":
    main()
