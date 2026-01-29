"""
Operational cost-benefit analysis for healthcare deployment.
Compares CyberCane costs vs. unmitigated phishing risk.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd


@dataclass
class CostAnalysis:
    """Operational cost breakdown."""

    daily_emails: int
    phishing_rate: float  # Base rate of phishing in email stream

    # Detection performance
    detection_recall: float
    false_positive_rate: float

    # API costs (per email)
    embedding_cost_per_email: float = 0.00002  # OpenAI text-embedding-3-small
    llm_cost_per_review: float = 0.001  # GPT-4o-mini per needs_review case

    # Labor costs
    analyst_hourly_rate: float = 30.0
    minutes_per_review: float = 2.0

    # Impact costs
    false_positive_delay_minutes: float = 15.0
    clinical_hourly_cost: float = 50.0  # Cost of delayed clinical communication
    breach_cost_per_incident: float = 50000.0  # Average HIPAA breach penalty


def compute_daily_costs(config: CostAnalysis) -> dict:
    """Compute daily operational costs and savings."""

    # Email volumes
    daily_phishing = config.daily_emails * config.phishing_rate
    daily_legitimate = config.daily_emails * (1 - config.phishing_rate)

    # Detection outcomes
    true_positives = daily_phishing * config.detection_recall
    false_negatives = daily_phishing * (1 - config.detection_recall)
    false_positives = daily_legitimate * config.false_positive_rate
    true_negatives = daily_legitimate * (1 - config.false_positive_rate)

    # API costs (all emails get embeddings, reviews get LLM reasoning)
    needs_review_rate = 0.131  # From manuscript: 13.1% escalate to needs_review
    embedding_cost_daily = config.daily_emails * config.embedding_cost_per_email * 2  # subject + body
    llm_cost_daily = config.daily_emails * needs_review_rate * config.llm_cost_per_review
    api_cost_total = embedding_cost_daily + llm_cost_daily

    # Human review costs (needs_review emails)
    reviews_per_day = config.daily_emails * needs_review_rate
    review_labor_hours = (reviews_per_day * config.minutes_per_review) / 60
    review_labor_cost = review_labor_hours * config.analyst_hourly_rate

    # False positive impact costs (delayed clinical communications)
    fp_delay_hours = (false_positives * config.false_positive_delay_minutes) / 60
    fp_impact_cost = fp_delay_hours * config.clinical_hourly_cost

    # Total daily operational cost
    total_daily_cost = api_cost_total + review_labor_cost + fp_impact_cost

    # Risk mitigation value (prevented breaches)
    detected_attacks = true_positives
    # Assume 10% of undetected phishing leads to successful breach
    prevented_breaches = detected_attacks * 0.10
    breach_risk_mitigated = prevented_breaches * config.breach_cost_per_incident

    # Unmitigated risk (if no detection system)
    unmitigated_breaches_per_day = daily_phishing * 0.10  # 10% success rate
    unmitigated_daily_risk = unmitigated_breaches_per_day * config.breach_cost_per_incident

    return {
        "daily_emails": config.daily_emails,
        "daily_phishing": daily_phishing,
        "daily_legitimate": daily_legitimate,
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "embedding_cost_daily": embedding_cost_daily,
        "llm_cost_daily": llm_cost_daily,
        "api_cost_total": api_cost_total,
        "reviews_per_day": reviews_per_day,
        "review_labor_cost": review_labor_cost,
        "fp_impact_cost": fp_impact_cost,
        "total_daily_cost": total_daily_cost,
        "detected_attacks": detected_attacks,
        "prevented_breaches": prevented_breaches,
        "breach_risk_mitigated": breach_risk_mitigated,
        "unmitigated_daily_risk": unmitigated_daily_risk,
        "net_benefit": breach_risk_mitigated - total_daily_cost,
        "roi": (
            (breach_risk_mitigated - total_daily_cost) / total_daily_cost
            if total_daily_cost > 0
            else 0
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Cost-benefit analysis for CyberCane deployment")
    parser.add_argument(
        "--daily-emails", type=int, default=10000, help="Daily email volume (default: 10,000)"
    )
    parser.add_argument(
        "--phishing-rate",
        type=float,
        default=0.044,
        help="Base phishing rate (default: 4.4%% from test data)",
    )
    parser.add_argument(
        "--recall", type=float, default=0.178, help="Detection recall (default: 17.8%%)"
    )
    parser.add_argument(
        "--fpr", type=float, default=0.0016, help="False positive rate (default: 0.16%%)"
    )
    args = parser.parse_args()

    # Create cost analysis configuration
    config = CostAnalysis(
        daily_emails=args.daily_emails,
        phishing_rate=args.phishing_rate,
        detection_recall=args.recall,
        false_positive_rate=args.fpr,
    )

    # Compute costs
    results = compute_daily_costs(config)

    # Create output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path("reports") / f"cost_benefit_{ts}"
    tab_dir = out_dir / "tables"
    tab_dir.mkdir(parents=True, exist_ok=True)

    # Save detailed breakdown
    breakdown_rows = [
        {"category": "API Costs", "item": "Embedding API (all emails)", "daily_cost": results["embedding_cost_daily"]},
        {"category": "API Costs", "item": "LLM reasoning (needs_review)", "daily_cost": results["llm_cost_daily"]},
        {"category": "API Costs", "item": "Total API", "daily_cost": results["api_cost_total"]},
        {"category": "Labor Costs", "item": f"Human review ({results['reviews_per_day']:.0f} emails)", "daily_cost": results["review_labor_cost"]},
        {"category": "Impact Costs", "item": f"False positive delays ({results['false_positives']:.0f} FPs)", "daily_cost": results["fp_impact_cost"]},
        {"category": "Total", "item": "Total Daily Cost", "daily_cost": results["total_daily_cost"]},
    ]
    breakdown_df = pd.DataFrame(breakdown_rows)
    breakdown_df.to_csv(tab_dir / "cost_breakdown.csv", index=False)

    # Save ROI summary
    roi_rows = [
        {
            "metric": "Total Daily Cost",
            "value": f"${results['total_daily_cost']:.2f}",
            "description": "API + labor + FP impact",
        },
        {
            "metric": "Attacks Detected",
            "value": f"{results['detected_attacks']:.1f}",
            "description": f"{config.detection_recall:.1%} of {results['daily_phishing']:.0f} daily phishing",
        },
        {
            "metric": "Breaches Prevented",
            "value": f"{results['prevented_breaches']:.2f}",
            "description": "10% attack success rate assumed",
        },
        {
            "metric": "Risk Mitigated",
            "value": f"${results['breach_risk_mitigated']:.2f}",
            "description": f"${config.breach_cost_per_incident:,.0f} per breach",
        },
        {
            "metric": "Net Daily Benefit",
            "value": f"${results['net_benefit']:.2f}",
            "description": "Risk mitigated - operational cost",
        },
        {
            "metric": "ROI",
            "value": f"{results['roi']:.1f}x",
            "description": "Return on investment",
        },
    ]
    roi_df = pd.DataFrame(roi_rows)
    roi_df.to_csv(tab_dir / "roi_summary.csv", index=False)

    # Save comparison vs. unmitigated risk
    comparison_rows = [
        {
            "scenario": "No Detection System",
            "daily_risk": results["unmitigated_daily_risk"],
            "daily_cost": 0,
            "net_position": -results["unmitigated_daily_risk"],
        },
        {
            "scenario": "CyberCane Deployment",
            "daily_risk": results["unmitigated_daily_risk"] - results["breach_risk_mitigated"],
            "daily_cost": results["total_daily_cost"],
            "net_position": results["net_benefit"],
        },
    ]
    comparison_df = pd.DataFrame(comparison_rows)
    comparison_df.to_csv(tab_dir / "scenario_comparison.csv", index=False)

    # Print summary
    print("\n" + "=" * 70)
    print("COST-BENEFIT ANALYSIS FOR CYBERCANE DEPLOYMENT")
    print("=" * 70)
    print(f"\nConfiguration:")
    print(f"  Daily email volume:     {config.daily_emails:,}")
    print(f"  Phishing base rate:     {config.phishing_rate:.1%}")
    print(f"  Detection recall:       {config.detection_recall:.1%}")
    print(f"  False positive rate:    {config.false_positive_rate:.2%}")

    print(f"\nDaily Email Classification:")
    print(f"  Phishing emails:        {results['daily_phishing']:.0f}")
    print(f"  Legitimate emails:      {results['daily_legitimate']:.0f}")
    print(f"  True positives:         {results['true_positives']:.0f}")
    print(f"  False negatives:        {results['false_negatives']:.0f}")
    print(f"  False positives:        {results['false_positives']:.0f}")
    print(f"  True negatives:         {results['true_negatives']:.0f}")

    print(f"\nOperational Costs (Daily):")
    print(f"  Embedding API:          ${results['embedding_cost_daily']:.2f}")
    print(f"  LLM reasoning:          ${results['llm_cost_daily']:.2f}")
    print(f"  Human review labor:     ${results['review_labor_cost']:.2f}")
    print(f"  FP delay impact:        ${results['fp_impact_cost']:.2f}")
    print(f"  ────────────────────────────────────")
    print(f"  Total daily cost:       ${results['total_daily_cost']:.2f}")

    print(f"\nRisk Mitigation:")
    print(f"  Attacks detected:       {results['detected_attacks']:.1f}")
    print(f"  Breaches prevented:     {results['prevented_breaches']:.2f}")
    print(f"  Risk mitigated:         ${results['breach_risk_mitigated']:.2f}")

    print(f"\nReturn on Investment:")
    print(f"  Net daily benefit:      ${results['net_benefit']:.2f}")
    print(f"  ROI:                    {results['roi']:.1f}x")
    print(f"  Monthly benefit:        ${results['net_benefit'] * 30:.2f}")
    print(f"  Annual benefit:         ${results['net_benefit'] * 365:.2f}")

    print(f"\nComparison:")
    print(f"  Unmitigated daily risk: ${results['unmitigated_daily_risk']:.2f}")
    print(f"  With CyberCane:         ${results['total_daily_cost']:.2f} (cost)")
    print(f"  Net improvement:        ${results['net_benefit']:.2f} (benefit)")

    print(f"\nResults saved to: {out_dir}")
    print("=" * 70)


if __name__ == "__main__":
    main()
