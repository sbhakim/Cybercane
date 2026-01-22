"""
Tune RAG similarity thresholds on validation set using grid search.

Usage:
    DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/app \
    PYTHONPATH=api /home/safayat/anaconda3/envs/cybercane/bin/python \
    api/app/evaluation/tune_dataphish_thresholds.py --neighbors 8 --limit 2000
"""

import argparse
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
import numpy as np

from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact
from app.ai_service import service as ai_service

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Sample:
    label: int
    phase1_verdict: str
    top_sim: float
    avg_top3: float


def load_validation_data(limit: int = None) -> pd.DataFrame:
    """Load validation split from JSONL."""
    repo_root = Path(__file__).resolve().parents[3]
    val_file = repo_root / "datasets" / "dataphish_val.jsonl"

    data = []
    with open(val_file, 'r', encoding='utf-8') as f:
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

    logger.info(f"Loaded {len(df)} validation emails")
    return df

def _build_samples(df: pd.DataFrame, neighbors_k: int) -> List[Sample]:
    """
    Precompute Phase 1 verdicts and RAG similarity stats once per email.

    This avoids LLM calls entirely and prevents recomputing embeddings
    for every threshold combination.
    """
    samples: List[Sample] = []
    total = len(df)

    for idx, row in df.iterrows():
        subject = str(row["subject"] or "")
        body = str(row["body"] or "")
        sender = str(row["sender"] or "")
        true_label = int(row["label"])

        redacted_body, _ = redact(body)
        phase1 = score_email(
            sender=sender,
            subject=subject,
            body=redacted_body,
            url_flag=1 if "http" in body.lower() else 0,
            enable_dns_checks=False,
        )

        doc_text = f"{subject}\n\n{redacted_body}".strip()
        vec = ai_service._embed_text(doc_text)
        neighbors = ai_service._nearest_neighbors(vec, limit=neighbors_k)
        similarities = sorted([n.similarity for n in neighbors], reverse=True)

        top_sim = similarities[0] if similarities else 0.0
        avg_top3 = sum(similarities[:3]) / min(3, len(similarities)) if similarities else 0.0

        samples.append(
            Sample(
                label=true_label,
                phase1_verdict=phase1.verdict,
                top_sim=top_sim,
                avg_top3=avg_top3,
            )
        )

        if (idx + 1) % 25 == 0:
            logger.info(f"Precomputed {idx + 1}/{total} samples")

    return samples


def evaluate_with_thresholds(
    samples: List[Sample],
    top_sim_threshold: float,
    avg_top3_threshold: float,
) -> Dict[str, float]:
    """
    Evaluate thresholds against precomputed samples.
    Returns metrics: precision, recall, F1, FPR
    """
    tp = fp = fn = tn = 0

    for sample in samples:
        if sample.phase1_verdict == "phishing":
            predicted_label = 1
        elif sample.top_sim >= top_sim_threshold:
            predicted_label = 1
        elif sample.phase1_verdict == "needs_review" and sample.avg_top3 >= avg_top3_threshold:
            predicted_label = 1
        elif sample.top_sim >= (top_sim_threshold - 0.15) or sample.avg_top3 >= (avg_top3_threshold - 0.18):
            predicted_label = 0  # needs_review threshold
        else:
            predicted_label = 0

        if sample.label == 1 and predicted_label == 1:
            tp += 1
        elif sample.label == 0 and predicted_label == 1:
            fp += 1
        elif sample.label == 1 and predicted_label == 0:
            fn += 1
        else:
            tn += 1

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
    }

def grid_search_thresholds(df: pd.DataFrame, neighbors_k: int) -> Tuple[float, float, Dict]:
    """
    Grid search over threshold combinations.

    Returns:
        (best_top_sim, best_avg_top3, best_metrics)
    """
    # Define search grid
    top_sim_range = np.arange(0.40, 0.76, 0.05)  # 0.40, 0.45, ..., 0.75
    avg_top3_range = np.arange(0.35, 0.71, 0.05)  # 0.35, 0.40, ..., 0.70

    best_f1 = 0.0
    best_thresholds = (0.55, 0.50)
    best_metrics = {}
    results = []

    logger.info(f"\nStarting grid search:")
    logger.info(f"  top_sim range: {top_sim_range[0]:.2f} to {top_sim_range[-1]:.2f}")
    logger.info(f"  avg_top3 range: {avg_top3_range[0]:.2f} to {avg_top3_range[-1]:.2f}")
    logger.info(f"  Total combinations: {len(top_sim_range) * len(avg_top3_range)}")

    logger.info("\nPrecomputing similarity stats (embeddings + retrieval once per email)...")
    samples = _build_samples(df, neighbors_k)
    logger.info(f"Precomputed {len(samples)} samples")

    for top_sim in top_sim_range:
        for avg_top3 in avg_top3_range:
            logger.info(f"\nTesting: top_sim={top_sim:.2f}, avg_top3={avg_top3:.2f}")

            metrics = evaluate_with_thresholds(samples, top_sim, avg_top3)

            results.append({
                "top_sim_threshold": top_sim,
                "avg_top3_threshold": avg_top3,
                **metrics
            })

            logger.info(f"  Precision: {metrics['precision']:.3f}, Recall: {metrics['recall']:.3f}, "
                       f"F1: {metrics['f1']:.3f}, FPR: {metrics['fpr']:.3f}")

            # Update best if F1 improved AND precision >= 0.93
            if metrics['f1'] > best_f1 and metrics['precision'] >= 0.93:
                best_f1 = metrics['f1']
                best_thresholds = (top_sim, avg_top3)
                best_metrics = metrics
                logger.info(f"  ★ NEW BEST! F1={best_f1:.3f}")

    # Save grid search results
    repo_root = Path(__file__).resolve().parents[3]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_file = repo_root / "datasets" / f"threshold_grid_search_{ts}.csv"
    pd.DataFrame(results).to_csv(results_file, index=False)
    logger.info(f"\nGrid search results saved to {results_file}")

    return best_thresholds[0], best_thresholds[1], best_metrics

def main():
    parser = argparse.ArgumentParser(description="Tune RAG thresholds on validation set")
    parser.add_argument("--neighbors", type=int, default=8, help="Number of neighbors (k)")
    parser.add_argument("--limit", type=int, default=None, help="Limit validation samples (for testing)")
    args = parser.parse_args()

    logger.info("="*70)
    logger.info("DataPhish Threshold Tuning (Grid Search)")
    logger.info("="*70)

    # Load validation data
    df = load_validation_data(limit=args.limit)

    # Grid search
    best_top_sim, best_avg_top3, best_metrics = grid_search_thresholds(df, args.neighbors)

    # Report results
    print("\n" + "="*70)
    print("OPTIMAL THRESHOLDS FOUND")
    print("="*70)
    print(f"  top_similarity threshold: {best_top_sim:.2f}")
    print(f"  avg_top3_sim threshold:   {best_avg_top3:.2f}")
    print(f"\nPerformance with optimal thresholds:")
    print(f"  Precision: {best_metrics['precision']:.1%}")
    print(f"  Recall:    {best_metrics['recall']:.1%}")
    print(f"  F1-score:  {best_metrics['f1']:.3f}")
    print(f"  FPR:       {best_metrics['fpr']:.2%}")
    print(f"  TP={best_metrics['tp']}, FP={best_metrics['fp']}, "
          f"FN={best_metrics['fn']}, TN={best_metrics['tn']}")
    print("="*70)

    # Save best thresholds
    repo_root = Path(__file__).resolve().parents[3]
    thresholds_file = repo_root / "datasets" / "best_thresholds_dataphish.json"
    with open(thresholds_file, 'w') as f:
        json.dump({
            "top_similarity_threshold": best_top_sim,
            "avg_top3_threshold": best_avg_top3,
            "neighbors_k": args.neighbors,
            "metrics": best_metrics,
            "tuned_on": "dataphish_val",
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)

    logger.info(f"\n✓ Saved thresholds to {thresholds_file}")
    logger.info("\nNext step: Update api/app/ai_service/service.py with these thresholds")

if __name__ == "__main__":
    main()
