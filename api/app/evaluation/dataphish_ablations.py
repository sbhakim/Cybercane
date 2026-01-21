"""
Ablation studies for DataPhish evaluation.

Tests different configurations:
- Neighbor counts (k=4, 8, 16, 32)
- Embedding models (if available)
- With/without ontology reasoning

Usage:
    DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/app \
    PYTHONPATH=api /home/safayat/anaconda3/envs/cybercane/bin/python \
    api/app/evaluation/dataphish_ablations.py --limit 500
"""

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import pandas as pd

from app.schemas import EmailIn, ScanOut, RedactionsOut
from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact
from app.ai_service.service import analyze_email

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_test_data(limit: int = None) -> pd.DataFrame:
    """Load test split."""
    repo_root = Path(__file__).resolve().parents[3]
    test_file = repo_root / "datasets" / "dataphish_test.jsonl"

    data = []
    with open(test_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                row = json.loads(line)
                label = 1 if row.get("Type") in ["Phishing", "Spam", "Phishing Simulation"] else 0
                entry = {
                    "subject": row.get("Subject", ""),
                    "body": row.get("Body", ""),
                    "sender": row.get("Sender", ""),
                    "label": label
                }
                data.append(entry)
            except json.JSONDecodeError:
                continue

    df = pd.DataFrame(data)
    if limit:
        df = df.head(limit)

    return df

def evaluate_configuration(df: pd.DataFrame, neighbors_k: int, use_ontology: bool = True) -> Dict[str, float]:
    """
    Evaluate with specific configuration.

    Returns metrics dict.
    """
    tp = fp = fn = tn = 0
    ontology_fires = 0

    for idx, row in df.iterrows():
        subject = str(row["subject"] or "")
        body = str(row["body"] or "")
        sender = str(row["sender"] or "")
        true_label = row["label"]

        # Phase 1
        redacted_body, redaction_counts = redact(body)
        phase1 = score_email(
            sender=sender,
            subject=subject,
            body=redacted_body,
            url_flag=1 if "http" in body.lower() else 0,
            enable_dns_checks=False
        )

        # Phase 2 RAG
        try:
            email_in = EmailIn(subject=subject, body=redacted_body, sender=sender, url=0)
            scan_out = ScanOut(
                verdict=phase1.verdict,
                score=phase1.score,
                reasons=phase1.reasons,
                indicators=phase1.indicators,
                redactions=RedactionsOut(types=redaction_counts, count=sum(redaction_counts.values())),
                redacted_body=redacted_body
            )

            ai_out = analyze_email(
                email_in,
                scan_out,
                neighbors_k=neighbors_k,
                include_ontology_context=use_ontology
            )

            predicted_label = 1 if ai_out.ai_verdict != "benign" else 0

            if use_ontology and ai_out.ontology_attacks:
                ontology_fires += 1

        except Exception as e:
            logger.error(f"Failed on row {idx}: {e}")
            predicted_label = 1 if phase1.verdict == "phishing" else 0

        # Update confusion matrix
        if true_label == 1 and predicted_label == 1:
            tp += 1
        elif true_label == 0 and predicted_label == 1:
            fp += 1
        elif true_label == 1 and predicted_label == 0:
            fn += 1
        else:
            tn += 1

        if (idx + 1) % 50 == 0:
            logger.info(f"  Processed {idx+1}/{len(df)}")

    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "ontology_fires": ontology_fires if use_ontology else None
    }

def main():
    parser = argparse.ArgumentParser(description="Ablation studies for DataPhish")
    parser.add_argument("--limit", type=int, default=500,
                        help="Limit test samples (for faster experiments)")
    args = parser.parse_args()

    logger.info("="*70)
    logger.info("DataPhish Ablation Studies")
    logger.info("="*70)

    # Load test data
    df = load_test_data(limit=args.limit)
    logger.info(f"Loaded {len(df)} test samples")

    results = []

    # Experiment 1: Vary neighbor count
    print("\n" + "="*70)
    print("ABLATION 1: Number of Neighbors (k)")
    print("="*70)

    for k in [4, 8, 16, 32]:
        print(f"\nTesting k={k}...")
        metrics = evaluate_configuration(df, neighbors_k=k, use_ontology=True)
        metrics["config"] = f"k={k}"
        metrics["neighbors_k"] = k
        metrics["ontology_enabled"] = True
        results.append(metrics)

        print(f"  Precision: {metrics['precision']:.3f}, Recall: {metrics['recall']:.3f}, "
              f"F1: {metrics['f1']:.3f}, FPR: {metrics['fpr']:.3f}")

    # Experiment 2: With/without ontology
    print("\n" + "="*70)
    print("ABLATION 2: Ontology Reasoning")
    print("="*70)

    for use_ont in [True, False]:
        config_name = "with_ontology" if use_ont else "no_ontology"
        print(f"\nTesting {config_name} (k=8)...")
        metrics = evaluate_configuration(df, neighbors_k=8, use_ontology=use_ont)
        metrics["config"] = config_name
        metrics["neighbors_k"] = 8
        metrics["ontology_enabled"] = use_ont
        results.append(metrics)

        print(f"  Precision: {metrics['precision']:.3f}, Recall: {metrics['recall']:.3f}, "
              f"F1: {metrics['f1']:.3f}")
        if use_ont:
            print(f"  Ontology fired: {metrics['ontology_fires']} times "
                  f"({metrics['ontology_fires']/len(df)*100:.1f}%)")

    # Save results
    repo_root = Path(__file__).resolve().parents[3]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = repo_root / "datasets" / f"ablation_results_{ts}.csv"
    pd.DataFrame(results).to_csv(results_file, index=False)

    print("\n" + "="*70)
    print("ABLATION SUMMARY")
    print("="*70)

    # Find best k
    k_results = [r for r in results if "k=" in r["config"]]
    best_k_result = max(k_results, key=lambda x: x["f1"])
    print(f"\nBest k: {best_k_result['neighbors_k']} (F1={best_k_result['f1']:.3f})")

    # Compare ontology
    with_ont = next(r for r in results if r["config"] == "with_ontology")
    without_ont = next(r for r in results if r["config"] == "no_ontology")
    print(f"\nOntology impact:")
    print(f"  With ontology:    F1={with_ont['f1']:.3f}, Recall={with_ont['recall']:.3f}")
    print(f"  Without ontology: F1={without_ont['f1']:.3f}, Recall={without_ont['recall']:.3f}")
    print(f"  Δ F1: {with_ont['f1'] - without_ont['f1']:+.3f}")

    print(f"\n✓ Results saved to {results_file}")
    print("="*70)

if __name__ == "__main__":
    main()
