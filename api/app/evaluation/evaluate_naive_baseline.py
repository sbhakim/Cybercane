"""
Evaluate CyberCane on naive phishing baseline.

This validates the system successfully detects unsophisticated attacks.
"""
from __future__ import annotations

import argparse
from typing import Dict, List

import pandas as pd

from app.evaluation import threshold_grid_evaluation as tge


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate naive phishing baseline")
    parser.add_argument(
        "--naive",
        default="reports/naive_phishing_baseline.csv",
        help="Naive phishing CSV",
    )
    parser.add_argument(
        "--test",
        default="reports/combined_eval_split_test.csv",
        help="Original test split (for benign sampling)",
    )
    parser.add_argument(
        "--output",
        default="reports/naive_baseline_results.csv",
        help="Output CSV for summary results",
    )
    parser.add_argument("--benign-sample", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--k", type=int, default=8)
    parser.add_argument("--enable-dns", action="store_true")
    parser.add_argument("--redact-embed", action="store_true")
    args = parser.parse_args()

    df_naive = pd.read_csv(args.naive)
    if "urls" not in df_naive.columns:
        df_naive["urls"] = 1
    if "sender" not in df_naive.columns:
        df_naive["sender"] = "unknown@example.com"
    if "label" not in df_naive.columns:
        df_naive["label"] = 1

    df_test = pd.read_csv(args.test)
    if "label" not in df_test.columns:
        raise ValueError("Test split must include label column")

    df_benign = df_test[df_test["label"] == 0].copy()
    if df_benign.empty:
        raise ValueError("No benign samples found")
    df_benign = df_benign.sample(n=min(args.benign_sample, len(df_benign)), random_state=args.seed)

    df_eval = pd.concat([df_naive, df_benign], ignore_index=True)

    configs = [
        tge.OperatingPoint(
            name="Baseline (Pipeline)",
            phase1_low=2,
            phase1_high=5,
            rag_sim_high=0.70,
            rag_sim_low=0.55,
            rag_avg_top3_high=0.68,
            rag_avg_top3_low=0.52,
            use_case="Current production thresholds",
        ),
        tge.OperatingPoint(
            name="Balanced",
            phase1_low=1,
            phase1_high=3,
            rag_sim_high=0.60,
            rag_sim_low=0.45,
            rag_avg_top3_high=0.55,
            rag_avg_top3_low=0.40,
            use_case="General healthcare organizations",
        ),
        tge.OperatingPoint(
            name="Aggressive",
            phase1_low=0,
            phase1_high=2,
            rag_sim_high=0.50,
            rag_sim_low=0.35,
            rag_avg_top3_high=0.45,
            rag_avg_top3_low=0.30,
            use_case="Maximum coverage",
        ),
    ]

    # Evaluate
    samples = tge._load_samples(
        df_eval,
        k_neighbors=args.k,
        enable_dns_checks=args.enable_dns,
        redact_for_embedding=args.redact_embed,
        total_rows=len(df_eval),
        progress_every=50,
    )

    rows: List[Dict[str, object]] = []
    for cfg in configs:
        metrics = tge._evaluate_config(samples, cfg)
        rows.append(
            {
                "operating_mode": cfg.name,
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "fpr": metrics["fpr"],
                "f1": metrics["f1"],
            }
        )

    summary_df = pd.DataFrame(rows)
    summary_df["dataset"] = "Naive Baseline"
    summary_df.to_csv(args.output, index=False)

    print(f"\n{'='*80}")
    print(f"NAIVE BASELINE EVALUATION RESULTS")
    print(f"{'='*80}")
    print(summary_df.to_string(index=False))
    print(f"\nWrote summary to {args.output}")

    # Per-category breakdown (Balanced mode)
    if "category" in df_naive.columns:
        print("\nPer-category (Balanced mode):")
        cat_rows = []
        for category in sorted(df_naive["category"].unique()):
            df_cat = df_naive[df_naive["category"] == category]
            df_cat_eval = pd.concat([df_cat, df_benign], ignore_index=True)
            cat_samples = tge._load_samples(
                df_cat_eval,
                k_neighbors=args.k,
                enable_dns_checks=args.enable_dns,
                redact_for_embedding=args.redact_embed,
                total_rows=len(df_cat_eval),
                progress_every=50,
            )
            cat_metrics = tge._evaluate_config(cat_samples, configs[1])  # Balanced mode
            cat_rows.append({
                "category": category,
                "precision": cat_metrics["precision"],
                "recall": cat_metrics["recall"],
            })
            print(f"  {category}: precision={cat_metrics['precision']:.1%}, "
                  f"recall={cat_metrics['recall']:.1%}")

        if cat_rows:
            out_cat = args.output.replace(".csv", "_by_category.csv")
            pd.DataFrame(cat_rows).to_csv(out_cat, index=False)
            print(f"\nWrote category breakdown to {out_cat}")


if __name__ == "__main__":
    main()
