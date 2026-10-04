"""
R1 + R3 for claim C1.

R1  Replication of the preregistered C1 pilot over split seeds 42, 1, 2, 3, 4.
R3  Conservative threshold rules applied to every method, to test whether
    CyberCane's advantage survives stronger baseline calibration defenses:
      - "budget":    validation-quantile threshold at the FPR budget (pilot rule)
      - "safety4":   threshold tuned for budget / 4
      - "zero_fp":   threshold at the maximum validation-negative score
    (Monotone recalibration such as Platt scaling cannot change quantile
    thresholds, so it is not a separate condition.)

Reuses the pilot's loaders and scorers unchanged. CPU only; no provider calls.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.replicate_c1
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.pilot_c1_shift import BUDGETS, WS, cp, fit_scorers, load

SETTINGS = (("nazsa", "dataphish"), ("nazsa", "nazsa"), ("dataphish", "dataphish"))


def thresholds(neg_val: np.ndarray, budget: float) -> dict:
    neg = np.sort(neg_val)

    def q(b):
        j = int(np.floor(len(neg) * (1 - b)))
        return neg[min(j, len(neg) - 1)]

    return {"budget": q(budget), "safety4": q(budget / 4), "zero_fp": neg[-1]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    ap.add_argument("--embed", default="text-embedding-3-small")
    args = ap.parse_args()
    out = WS / "reports_v2" / f"c1_replication_{args.embed}_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    for seed in args.seeds:
        for task in ("phish", "unwanted"):
            cache = {}

            def get(f, s):
                if (f, s) not in cache:
                    cache[(f, s)] = load(f, s, task, args.embed, seed=seed)
                return cache[(f, s)]

            for src, tgt in SETTINGS:
                setting = f"{src}->{tgt}" if src != tgt else f"in-domain {src}"
                score = fit_scorers(get(src, "train"))
                val, test = get(src, "val"), get(tgt, "test")
                sv, st = score(val), score(test)
                yv, yt = val.y.values, test.y.values
                nneg, npos = int((yt == 0).sum()), int((yt == 1).sum())
                for m in (k for k in st if not k.startswith("_")):
                    for b in BUDGETS:
                        for rule, thr in thresholds(sv[m][yv == 0], b).items():
                            if rule == "zero_fp" and b != BUDGETS[0]:
                                continue  # budget-independent; record once
                            pred = st[m] > thr
                            fp, tp = int(pred[yt == 0].sum()), int(pred[yt == 1].sum())
                            lo, hi = cp(fp, nneg)
                            rows.append(dict(seed=seed, task=task, setting=setting, method=m, rule=rule,
                                             budget=b if rule != "zero_fp" else None,
                                             test_fpr=fp / nneg, fpr_ci_lo=lo, fpr_ci_hi=hi,
                                             ratio=(fp / nneg) / b if rule != "zero_fp" else None,
                                             recall=tp / npos, fp=fp, n_neg=nneg, n_pos=npos))
                print(f"seed {seed} {task} {setting}: done", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="R1 seed replication + R3 conservative threshold rules for C1",
        seeds=args.seeds, embed=args.embed, budgets=BUDGETS, settings=SETTINGS,
        rules=["budget", "safety4", "zero_fp"], commit=commit, dns_policy="off"), indent=2))
    print("wrote", out)


if __name__ == "__main__":
    main()
