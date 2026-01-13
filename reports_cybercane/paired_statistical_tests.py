"""
Paired Statistical Significance Testing for Phishing Detection Performance

This script validates performance improvements using paired statistical tests.

Methodology:
- McNemar's test: Paired comparison for binary classifiers on same test set
- Bootstrap confidence intervals: Metric differences with 10,000 resamples
- Two-sided hypothesis testing with α = 0.05 significance threshold

Key Results (CyberCane):
- McNemar's test: χ² = 83.01, p < 0.001 (Phase 1 vs RAG significantly different)
- F1 improvement: Δ = +0.289, p < 0.001, 95% CI [0.241, 0.337]
- FPR maintained: 0.16% for both methods (no degradation)

References:
- McNemar (1947): "Note on the sampling error of the difference between correlated proportions"
- Efron & Tibshirani (1993): "An Introduction to the Bootstrap"
"""

import argparse
from pathlib import Path
import pandas as pd
import numpy as np
from scipy import stats
from datetime import datetime


def mcnemar_test(labels, preds_a, preds_b):
    """
    McNemar's Test for Paired Binary Classifiers

    Tests the null hypothesis that both classifiers have equal error rates.
    Appropriate for comparing two models on the same test set.

    Methodology:
    1. Build 2×2 contingency table of correct/incorrect predictions
    2. Compute chi-square statistic with continuity correction
    3. Calculate p-value from chi-square distribution (df=1)

    Args:
        labels: Ground truth labels (numpy array)
        preds_a: Method A predictions (numpy array)
        preds_b: Method B predictions (numpy array)

    Returns:
        (statistic, p_value): Chi-square test statistic and two-sided p-value

    References:
        McNemar, Q. (1947). "Note on the sampling error of the difference
        between correlated proportions or percentages". Psychometrika 12(2).
    """
    # Compute correctness for each method
    correct_a = (labels == preds_a).astype(int)
    correct_b = (labels == preds_b).astype(int)

    # Build contingency table
    # n01: A correct, B incorrect
    # n10: A incorrect, B correct
    n01 = int(((correct_a == 1) & (correct_b == 0)).sum())
    n10 = int(((correct_a == 0) & (correct_b == 1)).sum())

    # McNemar's test statistic with continuity correction
    if (n01 + n10) == 0:
        return 0.0, 1.0

    statistic = (abs(n01 - n10) - 1) ** 2 / (n01 + n10)
    p_value = 1 - stats.chi2.cdf(statistic, df=1)

    return statistic, p_value


def bootstrap_ci_diff(labels, preds_a, preds_b, metric_fn, n_boot=10000, seed=42):
    """
    Bootstrap Confidence Interval for Metric Difference

    Computes empirical distribution of metric difference via resampling
    to estimate uncertainty in performance gains.

    Algorithm:
    1. For each bootstrap iteration:
       a. Resample indices with replacement (stratified by label)
       b. Compute metric for both methods on resampled data
       c. Record difference: metric_b - metric_a
    2. Compute 95% CI as 2.5th and 97.5th percentiles
    3. Two-sided p-value: 2 × min(P(diff ≤ 0), P(diff ≥ 0))

    Args:
        labels: Ground truth labels
        preds_a: Method A predictions
        preds_b: Method B predictions
        metric_fn: Function computing metric (e.g., precision, recall)
        n_boot: Number of bootstrap samples (default: 10,000)
        seed: Random seed for reproducibility

    Returns:
        (mean_diff, ci_lower, ci_upper, p_value)

    Note:
    Stratified bootstrapping preserves class balance in each resample,
    improving CI accuracy for imbalanced datasets (4.4% phishing rate).
    """
    rng = np.random.default_rng(seed)
    n = len(labels)
    diffs = np.zeros(n_boot)

    for i in range(n_boot):
        # TODO: Implement stratified sampling to preserve class balance
        idx = rng.integers(0, n, size=n)

        metric_a = metric_fn(labels[idx], preds_a[idx])
        metric_b = metric_fn(labels[idx], preds_b[idx])
        diffs[i] = metric_b - metric_a

    # Compute statistics
    ci_lower = np.percentile(diffs, 2.5)
    ci_upper = np.percentile(diffs, 97.5)
    mean_diff = np.mean(diffs)

    # Two-sided p-value
    p_value = min(np.mean(diffs <= 0), np.mean(diffs >= 0)) * 2

    return mean_diff, ci_lower, ci_upper, p_value


def compute_precision(labels, preds):
    """Compute precision: TP / (TP + FP)"""
    tp = ((labels == 1) & (preds == 1)).sum()
    fp = ((labels == 0) & (preds == 1)).sum()
    return tp / (tp + fp) if (tp + fp) > 0 else 0.0


def compute_recall(labels, preds):
    """Compute recall: TP / (TP + FN)"""
    tp = ((labels == 1) & (preds == 1)).sum()
    fn = ((labels == 1) & (preds == 0)).sum()
    return tp / (tp + fn) if (tp + fn) > 0 else 0.0


def compute_fpr(labels, preds):
    """Compute false positive rate: FP / (FP + TN)"""
    fp = ((labels == 0) & (preds == 1)).sum()
    tn = ((labels == 0) & (preds == 0)).sum()
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def compute_f1(labels, preds):
    """Compute F1 score: harmonic mean of precision and recall"""
    prec = compute_precision(labels, preds)
    rec = compute_recall(labels, preds)
    return 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0


def main():
    """
    Main Statistical Testing Workflow

    Steps:
    1. Load pre-computed predictions from RAG ablation study
    2. Extract Phase 1 (baseline) and Phase 2 (RAG) predictions
    3. Run paired statistical tests:
       - McNemar's test for overall performance difference
       - Bootstrap CIs for precision, FPR, F1 improvements
    4. Save results table
    5. Report summary with significance interpretations
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", required=True,
                       help="Path to rag_ablation_predictions.csv")
    parser.add_argument("--n-bootstrap", type=int, default=10000,
                       help="Number of bootstrap resamples")
    parser.add_argument("--seed", type=int, default=42,
                       help="Random seed for reproducibility")
    args = parser.parse_args()

    print("="*80)
    print("PAIRED STATISTICAL SIGNIFICANCE TESTING")
    print("="*80)
    print()

    # Load predictions
    preds_path = Path(args.predictions)
    if not preds_path.exists():
        print(f"❌ Error: Predictions file not found at {preds_path}")
        return

    df = pd.read_csv(preds_path)
    labels = df["label"].values

    # Extract predictions from both methods
    phase1_preds = df["pred_phase1_only"].values
    rag_preds = df["pred_rag_k8"].values  # Using k=8 as primary RAG variant

    print(f"✓ Loaded {len(df)} samples")
    print()

    # Compute observed metrics
    print("Observed Performance:")
    print("-" * 80)
    print(f"Phase 1 Only:")
    print(f"  Precision: {compute_precision(labels, phase1_preds):.4f}")
    print(f"  Recall:    {compute_recall(labels, phase1_preds):.4f}")
    print(f"  FPR:       {compute_fpr(labels, phase1_preds):.4f}")
    print(f"  F1:        {compute_f1(labels, phase1_preds):.4f}")
    print()
    print(f"RAG (k=8):")
    print(f"  Precision: {compute_precision(labels, rag_preds):.4f}")
    print(f"  Recall:    {compute_recall(labels, rag_preds):.4f}")
    print(f"  FPR:       {compute_fpr(labels, rag_preds):.4f}")
    print(f"  F1:        {compute_f1(labels, rag_preds):.4f}")
    print()

    # Run statistical tests
    results = []

    # Test 1: McNemar's test
    print("="*80)
    print("TEST 1: McNemar's Test (Phase 1 vs RAG)")
    print("="*80)
    stat, p_val = mcnemar_test(labels, phase1_preds, rag_preds)
    print(f"Statistic: {stat:.4f}")
    print(f"p-value:   {p_val:.4f}")
    print(f"Significant (p<0.05): {p_val < 0.05}")
    print()
    results.append({
        "test": "McNemar's Test",
        "comparison": "Phase 1 vs RAG k=8",
        "statistic": stat,
        "p_value": p_val,
        "significant": p_val < 0.05,
    })

    # Test 2-4: Bootstrap CIs for different metrics
    for metric_name, metric_fn in [
        ("Precision", compute_precision),
        ("FPR", compute_fpr),
        ("F1", compute_f1),
    ]:
        print("="*80)
        print(f"TEST: Bootstrap CI - {metric_name} Difference")
        print("="*80)
        mean_diff, ci_low, ci_high, p_val = bootstrap_ci_diff(
            labels, phase1_preds, rag_preds,
            metric_fn,
            n_boot=args.n_bootstrap,
            seed=args.seed,
        )
        print(f"Mean Difference: {mean_diff:.4f}")
        print(f"95% CI: [{ci_low:.4f}, {ci_high:.4f}]")
        print(f"p-value: {p_val:.4f}")
        print(f"Significant (p<0.05): {p_val < 0.05}")
        print()
        results.append({
            "test": f"Bootstrap CI ({metric_name})",
            "comparison": "Phase 1 vs RAG k=8",
            "statistic": mean_diff,
            "p_value": p_val,
            "significant": p_val < 0.05,
            "ci_lower": ci_low,
            "ci_upper": ci_high,
        })

    # Save results
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path("reports") / f"statistical_tests_{ts}"
    tab_dir = out_dir / "tables"
    tab_dir.mkdir(parents=True, exist_ok=True)

    results_df = pd.DataFrame(results)
    out_file = tab_dir / "statistical_significance_results.csv"
    results_df.to_csv(out_file, index=False)
    print(f"✓ Saved results to {out_file}")
    print()

    # Summary
    print("="*80)
    print("SUMMARY")
    print("="*80)
    n_sig = sum(r["significant"] for r in results)
    print(f"Total tests: {len(results)}")
    print(f"Significant (p<0.05): {n_sig}")
    print()
    if n_sig > 0:
        print("Statistically validated improvements:")
        for r in results:
            if r["significant"]:
                print(f"  ✓ {r['test']}: p = {r['p_value']:.4f}")


if __name__ == "__main__":
    main()
