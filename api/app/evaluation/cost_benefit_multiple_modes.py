"""
Cost-benefit analysis across multiple operating modes.

Reads operating point metrics (precision/recall/FPR) and computes
daily costs, risk mitigation, and ROI for each mode using the same
assumptions as reports/cost_benefit_analysis.py.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Dict, List

import pandas as pd


@dataclass
class CostConfig:
    daily_emails: int = 10000
    phishing_rate: float = 0.044
    # API + labor assumptions (match reports/cost_benefit_analysis.py)
    embedding_cost_per_email: float = 0.00002
    llm_cost_per_review: float = 0.001
    analyst_hourly_rate: float = 30.0
    minutes_per_review: float = 2.0
    false_positive_delay_minutes: float = 15.0
    clinical_hourly_cost: float = 50.0
    breach_cost_per_incident: float = 50000.0
    needs_review_rate: float = 0.131


def compute_costs(recall: float, fpr: float, config: CostConfig) -> Dict[str, float]:
    daily_phishing = config.daily_emails * config.phishing_rate
    daily_legitimate = config.daily_emails * (1 - config.phishing_rate)

    attacks_detected = daily_phishing * recall
    false_positives = daily_legitimate * fpr
    breaches_prevented = attacks_detected * 0.10

    embedding_cost_daily = config.daily_emails * config.embedding_cost_per_email * 2
    llm_cost_daily = config.daily_emails * config.needs_review_rate * config.llm_cost_per_review
    api_cost_total = embedding_cost_daily + llm_cost_daily

    reviews_per_day = config.daily_emails * config.needs_review_rate
    review_labor_hours = (reviews_per_day * config.minutes_per_review) / 60
    review_labor_cost = review_labor_hours * config.analyst_hourly_rate

    fp_delay_hours = (false_positives * config.false_positive_delay_minutes) / 60
    fp_impact_cost = fp_delay_hours * config.clinical_hourly_cost

    total_daily_cost = api_cost_total + review_labor_cost + fp_impact_cost

    risk_mitigated = breaches_prevented * config.breach_cost_per_incident
    net_benefit = risk_mitigated - total_daily_cost
    roi = (net_benefit / total_daily_cost) if total_daily_cost > 0 else 0.0

    return {
        "attacks_detected": attacks_detected,
        "breaches_prevented": breaches_prevented,
        "false_positives": false_positives,
        "total_cost_daily": total_daily_cost,
        "risk_mitigated": risk_mitigated,
        "net_benefit": net_benefit,
        "roi": roi,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Cost-benefit analysis for multiple operating modes")
    parser.add_argument(
        "--input",
        default="reports/operating_points_evaluation.csv",
        help="Operating points CSV with precision/recall/FPR",
    )
    parser.add_argument(
        "--output",
        default="reports/cost_benefit_all_modes.csv",
        help="Output CSV path",
    )
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    if "recall" not in df.columns or "fpr" not in df.columns or "operating_mode" not in df.columns:
        raise ValueError("Input CSV must contain operating_mode, recall, and fpr columns")

    config = CostConfig()
    rows: List[Dict[str, float | str]] = []
    for _, row in df.iterrows():
        recall = float(row["recall"])
        fpr = float(row["fpr"])
        metrics = compute_costs(recall, fpr, config)
        rows.append(
            {
                "operating_mode": row["operating_mode"],
                "attacks_detected": metrics["attacks_detected"],
                "total_cost_daily": metrics["total_cost_daily"],
                "roi": metrics["roi"],
                "net_benefit": metrics["net_benefit"],
            }
        )

    out_df = pd.DataFrame(rows)
    out_df.to_csv(args.output, index=False)
    print(f"Wrote results to {args.output}")
    print(out_df.to_string(index=False))


if __name__ == "__main__":
    main()
