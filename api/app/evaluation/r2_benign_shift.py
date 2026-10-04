"""
R2: generality of the benign-shift result.

Protocol and success criteria were fixed before the run (R2, preregistration table in the paper).
  Forward (primary): source = Nazario phishing + benign B (train/val),
                     target = DataPhish test, decontaminated against source train.
  Reverse (descriptive): source = DataPhish train/val,
                     target = Nazario test phishing + B test ham, decontaminated.
  B in {spamassassin, ceas, ling}. Phish task. CPU only; no provider calls.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.r2_benign_shift
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.pilot_c1_shift import BUDGETS, WS, fit_scorers, load
from app.evaluation.r5_style_shift import concat, subset
from app.evaluation.replicate_c1 import thresholds
from app.evaluation.replicate_c1_decontam import XDUP, b11_scores, cluster_boot_fpr, cross_max_sim

EMBED = "text-embedding-3-small"
BENIGN = ("spamassassin", "ceas", "ling")


def tagged(df: pd.DataFrame, family: str) -> pd.DataFrame:
    """Prefix group ids by family so cluster ids never collide across corpora."""
    df["cgroup"] = family + ":" + df["group"].astype(str)
    return df


def nazario(split: str, seed: int) -> pd.DataFrame:
    d = load("nazsa", split, "phish", EMBED, seed=seed)
    return tagged(subset(d, d.source == "nazario"), "nazsa")


def benign(b: str, split: str, seed: int) -> pd.DataFrame:
    if b == "spamassassin":
        d = load("nazsa", split, "phish", EMBED, seed=seed)
        return tagged(subset(d, (d.source == "spamassassin") & (d.y == 0)), "nazsa")
    return tagged(load(b, split, "phish", EMBED, seed=seed), b)


def dataphish(split: str, seed: int) -> pd.DataFrame:
    return tagged(load("dataphish", split, "phish", EMBED, seed=seed), "dataphish")


def all_scores(train: pd.DataFrame, frames: list) -> list:
    score = fit_scorers(train)
    res = [{k: v for k, v in score(f).items() if not k.startswith("_")} for f in frames]
    for r, s in zip(res, b11_scores(train, frames)):
        r["B11_tfidf_phishonly_knn"] = s
    return res


def evaluate(direction, pair, seed, val, test, sv, st, rng):
    rows = []
    yv, yt, grp = val.y.values, test.y.values, test.cgroup.values
    nneg, npos = int((yt == 0).sum()), int((yt == 1).sum())
    for m, s_t in st.items():
        for b in BUDGETS:
            for rule, thr in thresholds(sv[m][yv == 0], b).items():
                if rule == "zero_fp" and b != BUDGETS[0]:
                    continue
                pred = s_t > thr
                fp, tp = int(pred[yt == 0].sum()), int(pred[yt == 1].sum())
                lo, hi = cluster_boot_fpr(pred[yt == 0], grp[yt == 0], rng)
                rows.append(dict(direction=direction, pair=pair, seed=seed, method=m, rule=rule,
                                 budget=b if rule != "zero_fp" else None, test_fpr=fp / nneg,
                                 boot_lo=lo, boot_hi=hi, recall=tp / npos, fp=fp, n_neg=nneg, n_pos=npos))
    return rows


def decontaminate(test: pd.DataFrame, train: pd.DataFrame) -> tuple:
    msim = cross_max_sim(test, train)
    bad = set(test.cgroup[msim >= XDUP])
    keep = ~test.cgroup.isin(bad).values
    return subset(test, keep), int((~keep).sum())


def criterion(res: pd.DataFrame, pair: str) -> dict:
    g = res[(res.direction == "forward") & (res.pair == pair) & (res.rule == "budget")]
    seed_ok = []
    for _, h in g.groupby("seed"):
        h = h.set_index(["method", "budget"]).test_fpr
        seed_ok.append(sum(h[("CC_full", b)] < min(h[("B3_tfidf_lr", b)], h[("B9_emb_lr", b)])
                           for b in BUDGETS) >= 2)
    one = g[g.budget == 0.01].groupby("method")[["test_fpr", "boot_lo", "boot_hi"]].mean()
    better = min(("B3_tfidf_lr", "B9_emb_lr"), key=lambda m: one.loc[m, "test_fpr"])
    sep = bool(one.loc["CC_full", "boot_hi"] < one.loc[better, "boot_lo"])
    return dict(pair=pair, seeds_meeting=int(sum(seed_ok)), ci_separated=sep, better_baseline=better,
                supports=bool(sum(seed_ok) >= 4 and sep))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"r2_benign_shift_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(0)
    rows, contam = [], []

    for seed in args.seeds:
        dp_test = dataphish("test", seed)
        dp_train, dp_val = dataphish("train", seed), dataphish("val", seed)
        for b in BENIGN:
            # Forward: public phishing + older benign -> DataPhish 2025
            src_tr = concat(nazario("train", seed), benign(b, "train", seed))
            src_va = concat(nazario("val", seed), benign(b, "val", seed))
            tgt, dropped = decontaminate(dp_test, src_tr)
            sv, st = all_scores(src_tr, [src_va, tgt])
            rows += evaluate("forward", b, seed, src_va, tgt, sv, st, rng)
            contam.append(dict(direction="forward", pair=b, seed=seed, dropped=dropped, kept=len(tgt)))

            # Reverse: DataPhish -> Nazario phishing + older benign
            rev = concat(nazario("test", seed), benign(b, "test", seed))
            rev, dropped = decontaminate(rev, dp_train)
            sv, st = all_scores(dp_train, [dp_val, rev])
            rows += evaluate("reverse", b, seed, dp_val, rev, sv, st, rng)
            contam.append(dict(direction="reverse", pair=b, seed=seed, dropped=dropped, kept=len(rev)))
            print(f"seed {seed} {b}: done", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)
    pd.DataFrame(contam).to_csv(out / "contamination.csv", index=False)
    crit = [criterion(res, b) for b in BENIGN]
    verdict = dict(pairs=crit, pairs_supporting=sum(c["supports"] for c in crit),
                   general=sum(c["supports"] for c in crit) >= 2)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="R2 preregistered benign-shift generality", seeds=args.seeds, embed=EMBED, budgets=BUDGETS,
        xdup=XDUP, benign_sources=BENIGN, commit=commit, criterion=verdict), indent=2))
    print("CRITERION", json.dumps(verdict))
    print("wrote", out)


if __name__ == "__main__":
    main()
