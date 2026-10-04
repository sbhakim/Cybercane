"""
Calibrate CyberCane's risk thresholds on source-validation negatives
Uses the same scorer as the experiments; no provider
calls. The phishing threshold targets the FPR budget; the review threshold a
wider budget (default 8x, the uncertain band used in E1).

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.scripts.calibrate_risk_thresholds \
      --benign spamassassin --seed 42 --budget 0.01 --out /path/to/risk_thresholds.json
"""

import argparse
import json
from datetime import datetime

import numpy as np

from app.evaluation.pilot_c1_shift import fit_scorers
from app.evaluation.r2_benign_shift import benign, nazario
from app.evaluation.r5_style_shift import concat
from app.evaluation.replicate_c1 import thresholds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", default="spamassassin", choices=["spamassassin", "ceas", "ling"])
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--budget", type=float, default=0.01)
    ap.add_argument("--review-factor", type=float, default=8.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    train = concat(nazario("train", args.seed), benign(args.benign, "train", args.seed))
    val = concat(nazario("val", args.seed), benign(args.benign, "val", args.seed))
    risk_val = fit_scorers(train)(val)["CC_full"]
    neg = np.sort(risk_val[val.y.values == 0])
    review_budget = min(args.budget * args.review_factor, 0.5)
    cfg = dict(
        risk_threshold_phishing=float(thresholds(neg, args.budget)["budget"]),
        risk_threshold_review=float(thresholds(neg, review_budget)["budget"]),
        fpr_budget=args.budget, review_budget=review_budget,
        calibrated_on=f"nazario+{args.benign} validation, split seed {args.seed}",
        n_validation_negatives=int(len(neg)),
        note="Calibrated on public corpora; realized FPR depends on how representative this benign set is of deployment mail.",
        created=datetime.now().isoformat(timespec="seconds"),
    )
    with open(args.out, "w") as f:
        json.dump(cfg, f, indent=2)
    print(json.dumps(cfg, indent=2))


if __name__ == "__main__":
    main()
