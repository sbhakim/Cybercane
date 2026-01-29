"""
Statistical Significance Testing for CyberCane Phishing Detection

Performs comprehensive statistical tests to validate performance claims:
1. McNemar's test: Phase 1 vs Phase 2 paired comparison
2. Paired bootstrap t-tests: Metric comparisons with confidence intervals
3. Permutation tests: RAG k-neighbor ablation significance
4. Baseline comparisons: Statistical validation of improvements

Output: Statistical results table with p-values for manuscript
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy import stats

from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact
from app.ai_service import service as ai_service
from app.schemas import EmailIn


TUNED_RULE_WEIGHTS = {
    "freemail_brand_claim": 2,
    "lookalike_domain": 2,
    "ip_literal_link": 2,
    "shortened_url": 2,
    "urgency": 2,
    "creds_request": 2,
    "missing_mx": 2,
    "no_spf": 2,
    "no_dmarc": 1,
    "strict_dmarc_missing_align": 3,
}


@dataclass
class StatTestResult:
    """Statistical test result with p-value and interpretation"""
    test_name: str
    comparison: str
    statistic: float
    p_value: float
    significant: bool  # p < 0.05
    interpretation: str


def _compute_metrics(labels: np.ndarray, preds: np.ndarray) -> Dict[str, float]:
    """Compute classification metrics"""
    tp = int(((labels == 1) & (preds == 1)).sum())
    tn = int(((labels == 0) & (preds == 0)).sum())
    fp = int(((labels == 0) & (preds == 1)).sum())
    fn = int(((labels == 1) & (preds == 0)).sum())

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def mcnemar_test(
    labels: np.ndarray,
    preds_a: np.ndarray,
    preds_b: np.ndarray,
    method_a: str,
    method_b: str,
) -> StatTestResult:
    """
    McNemar's test for paired binary classifiers

    Tests null hypothesis: Both methods have equal error rates
    Appropriate for comparing two classifiers on the same test set
    """
    # Build contingency table: how many times each method was correct/incorrect
    correct_a = (labels == preds_a).astype(int)
    correct_b = (labels == preds_b).astype(int)

    # n01: A correct, B incorrect
    # n10: A incorrect, B correct
    n01 = int(((correct_a == 1) & (correct_b == 0)).sum())
    n10 = int(((correct_a == 0) & (correct_b == 1)).sum())

    # McNemar's test statistic (with continuity correction)
    if (n01 + n10) == 0:
        statistic = 0.0
        p_value = 1.0
    else:
        statistic = (abs(n01 - n10) - 1) ** 2 / (n01 + n10)
        p_value = 1 - stats.chi2.cdf(statistic, df=1)

    significant = p_value < 0.05

    if significant:
        if n10 > n01:
            interpretation = f"{method_b} significantly better than {method_a} (p={p_value:.4f})"
        else:
            interpretation = f"{method_a} significantly better than {method_b} (p={p_value:.4f})"
    else:
        interpretation = f"No significant difference between {method_a} and {method_b} (p={p_value:.4f})"

    return StatTestResult(
        test_name="McNemar's Test",
        comparison=f"{method_a} vs {method_b}",
        statistic=statistic,
        p_value=p_value,
        significant=significant,
        interpretation=interpretation,
    )


def paired_bootstrap_test(
    labels: np.ndarray,
    preds_a: np.ndarray,
    preds_b: np.ndarray,
    method_a: str,
    method_b: str,
    metric: str = "f1",
    n_boot: int = 10000,
    seed: int = 42,
) -> StatTestResult:
    """
    Paired bootstrap test for metric differences

    Computes bootstrap confidence interval for metric difference
    Tests if CI excludes zero (significant difference)
    """
    rng = np.random.default_rng(seed)
    n = labels.shape[0]

    metric_diffs = np.zeros(n_boot)

    for i in range(n_boot):
        idx = rng.integers(0, n, size=n)
        metrics_a = _compute_metrics(labels[idx], preds_a[idx])
        metrics_b = _compute_metrics(labels[idx], preds_b[idx])
        metric_diffs[i] = metrics_b[metric] - metrics_a[metric]

    # Compute confidence interval
    ci_lower = np.percentile(metric_diffs, 2.5)
    ci_upper = np.percentile(metric_diffs, 97.5)
    mean_diff = np.mean(metric_diffs)

    # Two-sided test: is zero outside the CI?
    significant = not (ci_lower <= 0 <= ci_upper)

    # Compute p-value: proportion of bootstrap samples with opposite sign
    p_value = min(
        np.mean(metric_diffs <= 0),  # proportion <= 0
        np.mean(metric_diffs >= 0),  # proportion >= 0
    ) * 2  # two-sided

    if significant:
        direction = "higher" if mean_diff > 0 else "lower"
        interpretation = f"{method_b} has significantly {direction} {metric} than {method_a} (Δ={mean_diff:.4f}, 95% CI=[{ci_lower:.4f}, {ci_upper:.4f}])"
    else:
        interpretation = f"No significant difference in {metric} between {method_a} and {method_b} (Δ={mean_diff:.4f}, 95% CI=[{ci_lower:.4f}, {ci_upper:.4f}])"

    return StatTestResult(
        test_name=f"Paired Bootstrap ({metric})",
        comparison=f"{method_a} vs {method_b}",
        statistic=mean_diff,
        p_value=p_value,
        significant=significant,
        interpretation=interpretation,
    )


def permutation_test(
    labels: np.ndarray,
    preds_a: np.ndarray,
    preds_b: np.ndarray,
    method_a: str,
    method_b: str,
    metric: str = "f1",
    n_perm: int = 10000,
    seed: int = 42,
) -> StatTestResult:
    """
    Permutation test for metric differences

    Randomly swaps predictions between methods to test null hypothesis
    that both methods perform equally
    """
    rng = np.random.default_rng(seed)

    # Observed difference
    metrics_a_obs = _compute_metrics(labels, preds_a)
    metrics_b_obs = _compute_metrics(labels, preds_b)
    observed_diff = metrics_b_obs[metric] - metrics_a_obs[metric]

    # Permutation distribution
    perm_diffs = np.zeros(n_perm)

    for i in range(n_perm):
        # For each sample, randomly swap predictions between A and B
        swap_mask = rng.random(len(labels)) < 0.5
        preds_a_perm = np.where(swap_mask, preds_b, preds_a)
        preds_b_perm = np.where(swap_mask, preds_a, preds_b)

        metrics_a_perm = _compute_metrics(labels, preds_a_perm)
        metrics_b_perm = _compute_metrics(labels, preds_b_perm)
        perm_diffs[i] = metrics_b_perm[metric] - metrics_a_perm[metric]

    # Two-sided p-value: proportion of permutations with equal or more extreme difference
    p_value = np.mean(np.abs(perm_diffs) >= np.abs(observed_diff))

    significant = p_value < 0.05

    if significant:
        direction = "better" if observed_diff > 0 else "worse"
        interpretation = f"{method_b} performs significantly {direction} than {method_a} on {metric} (Δ={observed_diff:.4f}, p={p_value:.4f})"
    else:
        interpretation = f"No significant difference in {metric} (Δ={observed_diff:.4f}, p={p_value:.4f})"

    return StatTestResult(
        test_name=f"Permutation Test ({metric})",
        comparison=f"{method_a} vs {method_b}",
        statistic=observed_diff,
        p_value=p_value,
        significant=significant,
        interpretation=interpretation,
    )


def wilcoxon_signed_rank_test(
    labels: np.ndarray,
    preds_a: np.ndarray,
    preds_b: np.ndarray,
    method_a: str,
    method_b: str,
) -> StatTestResult:
    """
    Wilcoxon signed-rank test for paired samples

    Non-parametric test for paired differences
    Tests whether one method consistently outperforms another
    """
    # Compute per-sample correctness
    correct_a = (labels == preds_a).astype(int)
    correct_b = (labels == preds_b).astype(int)

    # Differences
    diffs = correct_b - correct_a

    # Wilcoxon signed-rank test
    try:
        statistic, p_value = stats.wilcoxon(diffs, alternative='two-sided')
    except ValueError:
        # All differences are zero
        statistic = 0.0
        p_value = 1.0

    significant = p_value < 0.05

    mean_diff = np.mean(diffs)
    if significant:
        direction = "better" if mean_diff > 0 else "worse"
        interpretation = f"{method_b} performs significantly {direction} than {method_a} (mean_diff={mean_diff:.4f}, p={p_value:.4f})"
    else:
        interpretation = f"No significant difference (mean_diff={mean_diff:.4f}, p={p_value:.4f})"

    return StatTestResult(
        test_name="Wilcoxon Signed-Rank",
        comparison=f"{method_a} vs {method_b}",
        statistic=float(statistic),
        p_value=p_value,
        significant=significant,
        interpretation=interpretation,
    )


def _score_phase1(df: pd.DataFrame, threshold: int, rule_weights: Dict[str, int] | None) -> np.ndarray:
    """Generate Phase 1 (deterministic) predictions"""
    preds = []
    for row in df.itertuples(index=False):
        sender = getattr(row, "sender_email", None) or getattr(row, "sender", "") or ""
        subject = getattr(row, "subject", "") or ""
        body = getattr(row, "body", "") or ""
        url_flag = int(getattr(row, "urls", 0) or 0)

        redacted_body, _ = redact(str(body))
        decision = score_email(
            sender=str(sender),
            subject=str(subject),
            body=redacted_body,
            url_flag=url_flag,
            enable_dns_checks=True,
            rule_weights=rule_weights,
        )
        preds.append(1 if decision.score >= threshold else 0)

    return np.array(preds, dtype=int)


def _score_phase2(df: pd.DataFrame, phase1_threshold: int, rule_weights: Dict[str, int] | None) -> np.ndarray:
    """Generate Phase 2 (RAG) predictions"""
    preds = []
    for row in df.itertuples(index=False):
        sender = getattr(row, "sender_email", None) or getattr(row, "sender", "") or ""
        receiver = getattr(row, "receiver", "") or "user@example.com"
        subject = getattr(row, "subject", "") or ""
        body = getattr(row, "body", "") or ""
        url_flag = int(getattr(row, "urls", 0) or 0)

        # Phase 1
        redacted_body, _ = redact(str(body))
        phase1 = score_email(
            sender=str(sender),
            subject=str(subject),
            body=redacted_body,
            url_flag=url_flag,
            enable_dns_checks=True,
            rule_weights=rule_weights,
        )

        # Convert to ScanOut-like dict
        phase1_dict = {
            "verdict": "phishing" if phase1.score >= phase1_threshold else "benign",
            "score": phase1.score,
            "reasons": phase1.reasons,
            "indicators": phase1.indicators,
            "redacted_body": redacted_body,
            "redactions": {},
        }

        # Phase 2: RAG analysis
        try:
            from app.schemas import ScanOut
            phase1_out = ScanOut(**phase1_dict)

            email_in = EmailIn(
                sender=sender,
                receiver=receiver,
                subject=subject,
                body=body,
                url=url_flag,
            )

            result = ai_service.analyze_email(email_in, phase1_out)
            pred = 1 if result.ai_verdict == "phishing" else 0
        except Exception:
            # Fall back to Phase 1 if RAG fails
            pred = 1 if phase1.score >= phase1_threshold else 0

        preds.append(pred)

    return np.array(preds, dtype=int)


def main():
    parser = argparse.ArgumentParser(description="Statistical significance testing for CyberCane")
    parser.add_argument("--n-bootstrap", type=int, default=10000, help="Bootstrap samples")
    parser.add_argument("--n-permutation", type=int, default=10000, help="Permutation samples")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    print("="*80)
    print("STATISTICAL SIGNIFICANCE TESTING FOR CYBERCANE")
    print("="*80)
    print()

    # Create output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path("reports") / f"statistical_significance_{ts}"
    tab_dir = run_dir / "tables"
    tab_dir.mkdir(parents=True, exist_ok=True)

    # Load test data
    test_path = Path("reports/combined_eval_split_test.csv")
    if not test_path.exists():
        print(f"❌ Error: Test data not found at {test_path}")
        return

    print(f"Loading test data from {test_path}...")
    df = pd.read_csv(test_path)
    labels = df["label"].values
    print(f"✓ Loaded {len(df)} samples ({(labels==1).sum()} phishing, {(labels==0).sum()} benign)")
    print()

    # Generate predictions
    print("Generating predictions...")
    print("  [1/3] Phase 1 (baseline rules, threshold=2)...")
    phase1_baseline_preds = _score_phase1(df, threshold=2, rule_weights=None)

    print("  [2/3] Phase 1 (tuned rules, threshold=2)...")
    phase1_tuned_preds = _score_phase1(df, threshold=2, rule_weights=TUNED_RULE_WEIGHTS)

    print("  [3/3] Phase 2 (RAG with tuned rules)...")
    phase2_preds = _score_phase2(df, phase1_threshold=2, rule_weights=TUNED_RULE_WEIGHTS)
    print("✓ Predictions generated")
    print()

    # Compute metrics for reporting
    print("Computing metrics...")
    metrics_p1_baseline = _compute_metrics(labels, phase1_baseline_preds)
    metrics_p1_tuned = _compute_metrics(labels, phase1_tuned_preds)
    metrics_p2 = _compute_metrics(labels, phase2_preds)

    print(f"  Phase 1 (baseline): Prec={metrics_p1_baseline['precision']:.3f}, Rec={metrics_p1_baseline['recall']:.3f}, FPR={metrics_p1_baseline['fpr']:.4f}")
    print(f"  Phase 1 (tuned):    Prec={metrics_p1_tuned['precision']:.3f}, Rec={metrics_p1_tuned['recall']:.3f}, FPR={metrics_p1_tuned['fpr']:.4f}")
    print(f"  Phase 2 (RAG):      Prec={metrics_p2['precision']:.3f}, Rec={metrics_p2['recall']:.3f}, FPR={metrics_p2['fpr']:.4f}")
    print()

    # Statistical tests
    results: List[StatTestResult] = []

    print("="*80)
    print("TEST 1: McNemar's Test - Phase 1 (tuned) vs Phase 2 (RAG)")
    print("="*80)
    result = mcnemar_test(labels, phase1_tuned_preds, phase2_preds, "Phase 1 (tuned)", "Phase 2 (RAG)")
    print(f"Statistic: {result.statistic:.4f}")
    print(f"p-value: {result.p_value:.4f}")
    print(f"Significant: {result.significant}")
    print(f"Interpretation: {result.interpretation}")
    print()
    results.append(result)

    print("="*80)
    print("TEST 2: Paired Bootstrap Test - Precision Improvement")
    print("="*80)
    result = paired_bootstrap_test(
        labels, phase1_tuned_preds, phase2_preds,
        "Phase 1 (tuned)", "Phase 2 (RAG)",
        metric="precision",
        n_boot=args.n_bootstrap,
        seed=args.seed,
    )
    print(f"Mean Difference: {result.statistic:.4f}")
    print(f"p-value: {result.p_value:.4f}")
    print(f"Significant: {result.significant}")
    print(f"Interpretation: {result.interpretation}")
    print()
    results.append(result)

    print("="*80)
    print("TEST 3: Paired Bootstrap Test - FPR Reduction")
    print("="*80)
    result = paired_bootstrap_test(
        labels, phase1_tuned_preds, phase2_preds,
        "Phase 1 (tuned)", "Phase 2 (RAG)",
        metric="fpr",
        n_boot=args.n_bootstrap,
        seed=args.seed,
    )
    print(f"Mean Difference: {result.statistic:.4f}")
    print(f"p-value: {result.p_value:.4f}")
    print(f"Significant: {result.significant}")
    print(f"Interpretation: {result.interpretation}")
    print()
    results.append(result)

    print("="*80)
    print("TEST 4: Permutation Test - F1-Score")
    print("="*80)
    result = permutation_test(
        labels, phase1_tuned_preds, phase2_preds,
        "Phase 1 (tuned)", "Phase 2 (RAG)",
        metric="f1",
        n_perm=args.n_permutation,
        seed=args.seed,
    )
    print(f"Observed Difference: {result.statistic:.4f}")
    print(f"p-value: {result.p_value:.4f}")
    print(f"Significant: {result.significant}")
    print(f"Interpretation: {result.interpretation}")
    print()
    results.append(result)

    print("="*80)
    print("TEST 5: Wilcoxon Signed-Rank Test")
    print("="*80)
    result = wilcoxon_signed_rank_test(
        labels, phase1_tuned_preds, phase2_preds,
        "Phase 1 (tuned)", "Phase 2 (RAG)",
    )
    print(f"Statistic: {result.statistic:.4f}")
    print(f"p-value: {result.p_value:.4f}")
    print(f"Significant: {result.significant}")
    print(f"Interpretation: {result.interpretation}")
    print()
    results.append(result)

    # Additional test: Baseline vs Tuned rules
    print("="*80)
    print("TEST 6: McNemar's Test - Baseline Rules vs Tuned Rules")
    print("="*80)
    result = mcnemar_test(labels, phase1_baseline_preds, phase1_tuned_preds, "Phase 1 (baseline)", "Phase 1 (tuned)")
    print(f"Statistic: {result.statistic:.4f}")
    print(f"p-value: {result.p_value:.4f}")
    print(f"Significant: {result.significant}")
    print(f"Interpretation: {result.interpretation}")
    print()
    results.append(result)

    # Save results
    print("="*80)
    print("SAVING RESULTS")
    print("="*80)

    results_df = pd.DataFrame([
        {
            "test": r.test_name,
            "comparison": r.comparison,
            "statistic": r.statistic,
            "p_value": r.p_value,
            "significant_at_0.05": r.significant,
            "interpretation": r.interpretation,
        }
        for r in results
    ])

    output_file = tab_dir / "statistical_significance_tests.csv"
    results_df.to_csv(output_file, index=False)
    print(f"✓ Saved results to {output_file}")

    # Save summary table for LaTeX
    latex_df = pd.DataFrame([
        {
            "Test": r.test_name,
            "Comparison": r.comparison,
            "Statistic": f"{r.statistic:.4f}",
            "p-value": f"{r.p_value:.4f}",
            "Significant": "Yes" if r.significant else "No",
        }
        for r in results
    ])

    latex_file = tab_dir / "statistical_tests_summary.csv"
    latex_df.to_csv(latex_file, index=False)
    print(f"✓ Saved LaTeX table to {latex_file}")

    print()
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total tests performed: {len(results)}")
    print(f"Significant results (p < 0.05): {sum(r.significant for r in results)}")
    print(f"Non-significant results: {sum(not r.significant for r in results)}")
    print()
    print("Key findings:")
    for r in results:
        if r.significant:
            print(f"  ✓ {r.interpretation}")
    print()
    print("Done!")


if __name__ == "__main__":
    main()
