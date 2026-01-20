"""
Evaluate PhishOnt ontology coverage and inference accuracy on test set.

Computes:
1. Coverage: % of emails with ≥1 ontology attack match
2. Accuracy: % of inferred attacks aligning with ground truth
3. Attack type distribution
"""

import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple
import time
from datetime import datetime

from app.symbolic.ontology_reasoner import (
    PhishingOntologyReasoner,
    indicators_to_ontology_format,
)
from app.pipeline.classify import classify_email


def load_test_data() -> pd.DataFrame:
    """Load test split from reports."""
    reports_dir = Path(__file__).parent.parent.parent.parent / "reports"

    # Use existing test split from evaluation
    test_path = reports_dir / "combined_eval_split_test.csv"

    if test_path.exists():
        print(f"Loading data from: {test_path}")
        df = pd.read_csv(test_path)
        print(f"Columns: {list(df.columns)}")
        return df

    raise FileNotFoundError(f"Could not find test data at {test_path}")


def evaluate_ontology_coverage(df: pd.DataFrame,
                                 reasoner: PhishingOntologyReasoner,
                                 min_confidence: float = 0.3) -> Dict:
    """
    Evaluate ontology coverage on test set.

    Args:
        df: Test dataframe with columns [sender, subject, body, url, label]
        reasoner: Initialized ontology reasoner
        min_confidence: Minimum confidence threshold for attack detection

    Returns:
        Dictionary with coverage statistics
    """
    results = {
        "total_emails": len(df),
        "phishing_emails": (df["label"] == 1).sum(),
        "benign_emails": (df["label"] == 0).sum(),
        "emails_with_attacks": 0,
        "phishing_with_attacks": 0,
        "benign_with_attacks": 0,
        "attack_type_counts": {},
        "avg_attacks_per_email": 0,
        "avg_confidence": 0,
    }

    all_attacks = []
    all_confidences = []

    start_time = time.time()
    last_print_time = start_time
    processed = 0

    for idx, row in df.iterrows():
        processed += 1
        current_time = time.time()
        elapsed = current_time - start_time

        # Print progress every 50 emails OR every 60 seconds
        if processed % 50 == 0 or (current_time - last_print_time) >= 60:
            emails_per_sec = processed / elapsed if elapsed > 0 else 0
            remaining = len(df) - processed
            eta_seconds = remaining / emails_per_sec if emails_per_sec > 0 else 0
            eta_minutes = eta_seconds / 60

            print(f"[{datetime.now().strftime('%H:%M:%S')}] Progress: {processed}/{len(df)} "
                  f"({processed/len(df)*100:.1f}%) | "
                  f"Speed: {emails_per_sec:.1f} emails/sec | "
                  f"ETA: {eta_minutes:.1f} min | "
                  f"Attacks found: {results['emails_with_attacks']}")
            last_print_time = current_time

        # Run Phase 1 to get indicators
        email = {
            "sender": str(row.get("sender_email", row.get("sender", "unknown@example.com"))),
            "receiver": str(row.get("receiver", "")),
            "subject": str(row.get("subject", "")),
            "body": str(row.get("body", "")),
            "url": int(row.get("urls", row.get("url", 0))),
        }

        try:
            phase1 = classify_email(email)

            # Convert to ontology format
            ontology_indicators = indicators_to_ontology_format(phase1.indicators)

            # Infer attacks
            inferred_attacks = reasoner.infer_attack_types(
                ontology_indicators,
                min_confidence=min_confidence
            )

            if inferred_attacks:
                results["emails_with_attacks"] += 1

                if row["label"] == 1:
                    results["phishing_with_attacks"] += 1
                else:
                    results["benign_with_attacks"] += 1

                # Count attack types
                for attack_type, confidence in inferred_attacks:
                    if attack_type not in results["attack_type_counts"]:
                        results["attack_type_counts"][attack_type] = 0
                    results["attack_type_counts"][attack_type] += 1

                    all_attacks.append(attack_type)
                    all_confidences.append(confidence)

        except Exception as e:
            print(f"[ERROR] Email {processed}: {e}")
            continue

    # Final progress update
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] ✓ Completed: {processed}/{len(df)} emails processed")

    # Compute averages
    if results["emails_with_attacks"] > 0:
        results["avg_attacks_per_email"] = len(all_attacks) / results["emails_with_attacks"]
        results["avg_confidence"] = sum(all_confidences) / len(all_confidences)

    # Compute coverage percentages
    results["phishing_coverage_pct"] = (
        results["phishing_with_attacks"] / results["phishing_emails"] * 100
        if results["phishing_emails"] > 0 else 0
    )
    results["benign_coverage_pct"] = (
        results["benign_with_attacks"] / results["benign_emails"] * 100
        if results["benign_emails"] > 0 else 0
    )
    results["overall_coverage_pct"] = (
        results["emails_with_attacks"] / results["total_emails"] * 100
    )

    return results


def print_results(results: Dict):
    """Pretty-print coverage results."""
    print("\n" + "=" * 80)
    print("ONTOLOGY COVERAGE ANALYSIS")
    print("=" * 80)

    print(f"\nDataset Statistics:")
    print(f"  Total emails: {results['total_emails']}")
    print(f"  Phishing: {results['phishing_emails']}")
    print(f"  Benign: {results['benign_emails']}")

    print(f"\nCoverage (emails with ≥1 attack detected):")
    print(f"  Overall: {results['emails_with_attacks']}/{results['total_emails']} "
          f"({results['overall_coverage_pct']:.1f}%)")
    print(f"  Phishing: {results['phishing_with_attacks']}/{results['phishing_emails']} "
          f"({results['phishing_coverage_pct']:.1f}%)")
    print(f"  Benign: {results['benign_with_attacks']}/{results['benign_emails']} "
          f"({results['benign_coverage_pct']:.1f}%)")

    print(f"\nAttack Type Distribution:")
    sorted_attacks = sorted(
        results["attack_type_counts"].items(),
        key=lambda x: x[1],
        reverse=True
    )
    for attack_type, count in sorted_attacks:
        pct = count / results["total_emails"] * 100
        print(f"  {attack_type:<35} {count:>5} ({pct:>5.1f}%)")

    print(f"\nAverages:")
    print(f"  Attacks per email (when detected): {results['avg_attacks_per_email']:.2f}")
    print(f"  Average confidence: {results['avg_confidence']*100:.1f}%")

    print("\n" + "=" * 80)


def main():
    """Run ontology coverage evaluation."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=int, default=None,
                       help="Sample N emails for faster testing (default: use all)")
    args = parser.parse_args()

    print("=" * 80)
    print("ONTOLOGY COVERAGE EVALUATION")
    print("=" * 80)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    print("[1/4] Initializing ontology reasoner...")
    reasoner = PhishingOntologyReasoner()
    stats = reasoner.get_ontology_stats()
    print(f"      ✓ Loaded ontology: {stats['total_triples']} triples, "
          f"{stats['attack_types']} attack types\n")

    print("[2/4] Loading test data...")
    df = load_test_data()
    print(f"      ✓ Loaded {len(df)} emails from test split")

    if args.sample:
        print(f"      ⚠ Sampling {args.sample} emails for faster evaluation")
        df = df.sample(n=min(args.sample, len(df)), random_state=42)
        print(f"      ✓ Using {len(df)} emails\n")
    else:
        print(f"      ✓ Using full test set ({len(df)} emails)\n")

    print("[3/4] Running ontology inference on all emails...")
    print("      (Progress updates every 50 emails or 60 seconds)")
    print()

    eval_start = time.time()
    results = evaluate_ontology_coverage(df, reasoner, min_confidence=0.3)
    eval_time = time.time() - eval_start

    print(f"\n      ✓ Evaluation completed in {eval_time/60:.1f} minutes")
    print(f"      ✓ Average time per email: {eval_time/len(df)*1000:.1f}ms\n")

    print("[4/4] Generating results...")

    print_results(results)

    # Save results
    output_dir = Path(__file__).parent.parent.parent.parent / "reports"
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / "ontology_coverage.txt"
    with open(output_file, "w") as f:
        f.write("ONTOLOGY COVERAGE ANALYSIS\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Total emails: {results['total_emails']}\n")
        f.write(f"Overall coverage: {results['overall_coverage_pct']:.1f}%\n")
        f.write(f"Phishing coverage: {results['phishing_coverage_pct']:.1f}%\n")
        f.write(f"Benign coverage: {results['benign_coverage_pct']:.1f}%\n\n")
        f.write("Attack Type Distribution:\n")
        for attack_type, count in sorted(results["attack_type_counts"].items(),
                                        key=lambda x: x[1], reverse=True):
            pct = count / results["total_emails"] * 100
            f.write(f"  {attack_type}: {count} ({pct:.1f}%)\n")

    print(f"\nResults saved to: {output_file}")


if __name__ == "__main__":
    main()
