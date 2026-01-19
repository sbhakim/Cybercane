"""
Evaluate CyberCane on synthetic healthcare phishing data.

Combines synthetic phishing with a benign sample from the test split
and reports operating-point metrics plus per-category breakdown.
"""
from __future__ import annotations

import argparse
import re
from typing import Dict, List

import pandas as pd

from app.evaluation import threshold_grid_evaluation as tge


def _url_flag_from_text(text: str) -> int:
    return 1 if re.search(r"(https?://|www\.)\S+", text or "") else 0


def _prepare_synthetic(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "urls" not in df.columns:
        df["urls"] = df["body"].fillna("").map(_url_flag_from_text)
    if "sender" not in df.columns:
        df["sender"] = "unknown@example.com"
    if "label" not in df.columns:
        df["label"] = 1
    return df


def _prepare_benign(df: pd.DataFrame, sample_n: int, seed: int) -> pd.DataFrame:
    df = df[df["label"] == 0].copy()
    if df.empty:
        raise ValueError("No benign samples found in test split")
    return df.sample(n=min(sample_n, len(df)), random_state=seed)


def _evaluate_configs(
    df_eval: pd.DataFrame,
    configs: List[tge.OperatingPoint],
    *,
    k_neighbors: int,
    enable_dns_checks: bool,
    redact_for_embedding: bool,
) -> pd.DataFrame:
    samples = tge._load_samples(
        df_eval,
        k_neighbors=k_neighbors,
        enable_dns_checks=enable_dns_checks,
        redact_for_embedding=redact_for_embedding,
        total_rows=len(df_eval),
        progress_every=100,
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
    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate synthetic healthcare phishing dataset")
    parser.add_argument(
        "--synthetic",
        default="reports/synthetic_healthcare_phishing.csv",
        help="Synthetic phishing CSV",
    )
    parser.add_argument(
        "--test",
        default="reports/combined_eval_split_test.csv",
        help="Original test split (for benign sampling)",
    )
    parser.add_argument(
        "--output",
        default="reports/healthcare_synthetic_results.csv",
        help="Output CSV for summary results",
    )
    parser.add_argument("--benign-sample", type=int, default=200)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--k", type=int, default=8)
    parser.add_argument("--enable-dns", action="store_true")
    parser.add_argument("--redact-embed", action="store_true")
    args = parser.parse_args()

    df_synth = pd.read_csv(args.synthetic)
    df_synth = _prepare_synthetic(df_synth)

    df_test = pd.read_csv(args.test)
    if "label" not in df_test.columns:
        raise ValueError("Test split must include label column")
    df_benign = _prepare_benign(df_test, args.benign_sample, args.seed)

    df_eval = pd.concat([df_synth, df_benign], ignore_index=True)

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

    summary_df = _evaluate_configs(
        df_eval,
        configs,
        k_neighbors=args.k,
        enable_dns_checks=args.enable_dns,
        redact_for_embedding=args.redact_embed,
    )
    summary_df["dataset"] = "Healthcare Synthetic"
    summary_df.to_csv(args.output, index=False)
    print(f"Wrote summary to {args.output}")
    print(summary_df.to_string(index=False))

    # Per-category breakdown (Balanced mode)
    if "category" in df_synth.columns:
        print("\nPer-category (Balanced mode):")
        cat_rows = []
        for category in sorted(df_synth["category"].unique()):
            df_cat = df_synth[df_synth["category"] == category]
            df_cat_eval = pd.concat([df_cat, df_benign], ignore_index=True)
            cat_df = _evaluate_configs(
                df_cat_eval,
                [configs[1]],
                k_neighbors=args.k,
                enable_dns_checks=args.enable_dns,
                redact_for_embedding=args.redact_embed,
            )
            cat_df["category"] = category
            cat_rows.append(cat_df)
            print(f"  {category}: precision={cat_df.loc[0, 'precision']:.1%}, "
                  f"recall={cat_df.loc[0, 'recall']:.1%}")

        if cat_rows:
            out_cat = args.output.replace(".csv", "_by_category.csv")
            pd.concat(cat_rows, ignore_index=True).to_csv(out_cat, index=False)
            print(f"Wrote category breakdown to {out_cat}")


if __name__ == "__main__":
    main()
