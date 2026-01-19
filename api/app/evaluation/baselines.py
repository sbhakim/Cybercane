from __future__ import annotations

import argparse
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple

import pandas as pd


@dataclass
class Metrics:
    name: str
    tp: int
    tn: int
    fp: int
    fn: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    fpr: float


@dataclass
class PrivacyCostMetrics:
    """Extended metrics tracking privacy and cost for GPT-4 baseline."""
    total_chars_transmitted: int
    avg_chars_per_email: float
    total_cost_usd: float
    avg_cost_per_email: float
    phi_patterns_detected: int
    emails_with_phi: int
    phi_exposure_rate: float


def _metrics_from_preds(labels: pd.Series, preds: pd.Series, name: str) -> Metrics:
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
    return Metrics(name, tp, tn, fp, fn, accuracy, precision, recall, f1, fpr)


def _prepare_text(df: pd.DataFrame) -> pd.Series:
    subject = df.get("subject", "").fillna("").astype(str)
    body = df.get("body", "").fillna("").astype(str)
    return (subject + "\n\n" + body).str.strip()


def _majority_baseline(labels: pd.Series) -> pd.Series:
    majority = int(labels.value_counts().idxmax())
    return pd.Series([majority] * len(labels))


def _tfidf_logreg(train_text: pd.Series, train_labels: pd.Series, test_text: pd.Series) -> pd.Series:
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
    except Exception as exc:
        raise RuntimeError("scikit-learn is required for TF-IDF baseline") from exc

    pipe = Pipeline(
        steps=[
            ("tfidf", TfidfVectorizer(max_features=20000, ngram_range=(1, 2))),
            ("clf", LogisticRegression(max_iter=1000, n_jobs=1)),
        ]
    )
    pipe.fit(train_text, train_labels)
    return pd.Series(pipe.predict(test_text))


def _detect_phi_patterns(text: str) -> Tuple[int, bool]:
    """
    Detect PHI patterns in text using regex.

    Returns:
        Tuple of (pattern_count, has_phi_bool)
    """
    phi_patterns = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit card
        r'\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/\d{4}\b',  # DOB
    ]

    count = 0
    for pattern in phi_patterns:
        count += len(re.findall(pattern, text, re.IGNORECASE))

    return count, count > 0


def _gpt4_direct_baseline(
    test_text: pd.Series,
    model: str = "gpt-4o-mini",
    rate_limit_delay: float = 0.5
) -> Tuple[pd.Series, PrivacyCostMetrics]:
    """
    GPT-4 direct baseline: send full unredacted emails to GPT-4.

    Demonstrates privacy/cost trade-offs of direct LLM use without CyberCane's
    privacy-preserving architecture.

    Args:
        test_text: Email texts (subject + body)
        model: OpenAI model name (default: gpt-4o-mini for cost)
        rate_limit_delay: Delay between API calls in seconds

    Returns:
        Tuple of (predictions Series, PrivacyCostMetrics)

    Raises:
        RuntimeError: If OpenAI API key not available
    """
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("openai package required for GPT-4 baseline") from exc

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable required for GPT-4 baseline")

    client = OpenAI(api_key=api_key)

    # Pricing (as of 2026-01, per 1M tokens)
    pricing = {
        "gpt-4o-mini": {"input": 0.150, "output": 0.600},  # $0.15/$0.60 per 1M tokens
        "gpt-4-turbo": {"input": 10.00, "output": 30.00},
        "gpt-4": {"input": 30.00, "output": 60.00},
    }

    model_pricing = pricing.get(model, pricing["gpt-4o-mini"])

    predictions = []
    total_chars = 0
    total_cost = 0.0
    phi_count_total = 0
    emails_with_phi = 0

    print(f"\n{'='*80}")
    print(f"GPT-4 DIRECT BASELINE: {model}")
    print(f"{'='*80}")
    print(f"Processing {len(test_text)} emails...")
    print(f"Rate limit delay: {rate_limit_delay}s between calls")

    for idx, email_text in enumerate(test_text, 1):
        # Track privacy metrics
        chars_transmitted = len(email_text)
        total_chars += chars_transmitted

        phi_count, has_phi = _detect_phi_patterns(email_text)
        phi_count_total += phi_count
        if has_phi:
            emails_with_phi += 1

        # Zero-shot prompt
        prompt = f"Is this email phishing? Answer only 'yes' or 'no'.\n\nEmail:\n{email_text}"

        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=10
            )

            # Parse response
            answer = response.choices[0].message.content.strip().lower()
            prediction = 1 if "yes" in answer else 0

            # Estimate cost (rough approximation: 4 chars ~ 1 token)
            input_tokens = len(prompt) / 4
            output_tokens = len(answer) / 4
            cost = (input_tokens * model_pricing["input"] / 1_000_000 +
                   output_tokens * model_pricing["output"] / 1_000_000)
            total_cost += cost

            predictions.append(prediction)

            # Progress indicator
            if idx % 50 == 0:
                print(f"  [{idx}/{len(test_text)}] Processed... "
                      f"Avg cost: ${total_cost/idx:.4f}/email, "
                      f"Avg chars: {total_chars/idx:.0f}/email")

        except Exception as e:
            print(f"  ⚠️  Error on email {idx}: {e}")
            predictions.append(0)  # Default to benign on error

        # Rate limiting
        time.sleep(rate_limit_delay)

    # Calculate metrics
    privacy_cost_metrics = PrivacyCostMetrics(
        total_chars_transmitted=total_chars,
        avg_chars_per_email=total_chars / len(test_text),
        total_cost_usd=total_cost,
        avg_cost_per_email=total_cost / len(test_text),
        phi_patterns_detected=phi_count_total,
        emails_with_phi=emails_with_phi,
        phi_exposure_rate=emails_with_phi / len(test_text)
    )

    print(f"\n{'='*80}")
    print("GPT-4 BASELINE SUMMARY")
    print(f"{'='*80}")
    print(f"Total emails processed: {len(test_text)}")
    print(f"Total characters transmitted: {total_chars:,}")
    print(f"Average chars/email: {privacy_cost_metrics.avg_chars_per_email:.0f}")
    print(f"Total cost: ${total_cost:.2f}")
    print(f"Average cost/email: ${privacy_cost_metrics.avg_cost_per_email:.4f}")
    print(f"PHI patterns detected: {phi_count_total}")
    print(f"Emails with PHI: {emails_with_phi} ({privacy_cost_metrics.phi_exposure_rate:.1%})")
    print(f"{'='*80}\n")

    return pd.Series(predictions), privacy_cost_metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Run text baselines on train/test splits")
    parser.add_argument(
        "--train",
        default="reports/combined_eval_split_train.csv",
        help="Path to train split CSV",
    )
    parser.add_argument(
        "--test",
        default="reports/combined_eval_split_test.csv",
        help="Path to test split CSV",
    )
    parser.add_argument(
        "--gpt4",
        action="store_true",
        help="Run GPT-4 direct baseline (requires OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--gpt4-model",
        default="gpt-4o-mini",
        help="GPT-4 model to use (default: gpt-4o-mini)",
    )
    parser.add_argument(
        "--gpt4-delay",
        type=float,
        default=0.5,
        help="Delay between GPT-4 API calls in seconds (default: 0.5)",
    )
    args = parser.parse_args()

    train_df = pd.read_csv(args.train)
    test_df = pd.read_csv(args.test)
    train_labels = train_df["label"].astype(int)
    test_labels = test_df["label"].astype(int)

    train_text = _prepare_text(train_df)
    test_text = _prepare_text(test_df)

    rows: List[Metrics] = []
    rows.append(_metrics_from_preds(test_labels, _majority_baseline(test_labels), "majority"))

    try:
        tfidf_preds = _tfidf_logreg(train_text, train_labels, test_text)
        rows.append(_metrics_from_preds(test_labels, tfidf_preds, "tfidf_logreg"))
    except RuntimeError as exc:
        print(str(exc))

    # GPT-4 direct baseline (optional, requires API key)
    privacy_cost_metrics = None
    if args.gpt4:
        try:
            gpt4_preds, privacy_cost_metrics = _gpt4_direct_baseline(
                test_text,
                model=args.gpt4_model,
                rate_limit_delay=args.gpt4_delay
            )
            rows.append(_metrics_from_preds(test_labels, gpt4_preds, f"gpt4_direct_{args.gpt4_model}"))
        except RuntimeError as exc:
            print(f"GPT-4 baseline failed: {exc}")

    out_dir = Path("reports") / f"baselines_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    tab_dir = out_dir / "tables"
    tab_dir.mkdir(parents=True, exist_ok=True)
    out_df = pd.DataFrame([r.__dict__ for r in rows])
    out_df.to_csv(tab_dir / "baseline_metrics.csv", index=False)

    # Save privacy/cost metrics if GPT-4 was run
    if privacy_cost_metrics:
        privacy_df = pd.DataFrame([privacy_cost_metrics.__dict__])
        privacy_df.to_csv(tab_dir / "gpt4_privacy_cost_metrics.csv", index=False)
        print(f"Privacy/cost metrics saved to {tab_dir / 'gpt4_privacy_cost_metrics.csv'}")

    print(f"\nResults saved to: {out_dir}")
    print(f"Baseline metrics: {tab_dir / 'baseline_metrics.csv'}")

    # Print summary table
    print(f"\n{'='*80}")
    print("BASELINE COMPARISON")
    print(f"{'='*80}")
    print(out_df.to_string(index=False))
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
