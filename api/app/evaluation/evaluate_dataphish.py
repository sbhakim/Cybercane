
import argparse
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact
from app.ai_service.service import analyze_email
from app.schemas import EmailIn, ScanOut, RedactionsOut

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PHASE1_THRESHOLD = 2
_URL_RE = re.compile(r"(https?://|www\.)\S+", re.IGNORECASE)


def _extract_url_flag(subject: str, body: str) -> int:
    """Detect whether the email contains at least one URL."""
    text = f"{subject}\n{body}"
    return 1 if _URL_RE.search(text) else 0


def load_dataphish(jsonl_path: Path) -> pd.DataFrame:
    """Load and normalize the DataPhish 2025 dataset."""
    logger.info(f"Loading dataset from {jsonl_path}")
    data = []
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                row = json.loads(line)
                
                # Map Type to binary label
                # Phishing/Spam -> 1, Valid -> 0
                label = 1 if row.get("Type") in ["Phishing", "Spam", "Phishing Simulation"] else 0
                
                # Extract emotions as list
                emotions = row.get("LLM detected emotion", [])
                
                entry = {
                    "subject": row.get("Subject", ""),
                    "body": row.get("Body", ""),
                    "sender": row.get("Sender", ""),
                    "label": label,
                    "original_type": row.get("Type"),
                    "created_by": row.get("Created by", "Unknown"),
                    "emotions": emotions,
                    "source": row.get("Source", "Unknown")
                }
                data.append(entry)
            except json.JSONDecodeError:
                continue
                
    return pd.DataFrame(data)

def evaluate_row(row: pd.Series, use_rag: bool = False) -> Dict[str, Any]:
    """Process a single row through the pipeline."""
    subject = str(row.get("subject", "") or "")
    body = str(row.get("body", "") or "")
    sender = str(row.get("sender", "") or "")
    url_flag = _extract_url_flag(subject, body)

    # Redact PII first
    redacted_body, redaction_counts = redact(body)

    # Phase 1: Deterministic
    # Note: enable_dns_checks=False because we don't have raw domains/headers to verify reliably
    phase1 = score_email(
        sender=sender,
        subject=subject,
        body=redacted_body,
        url_flag=url_flag,
        enable_dns_checks=False
    )

    result = {
        "label": row["label"],
        "phase1_score": phase1.score,
        "phase1_verdict": phase1.verdict,
        "phase1_pred": 1 if phase1.score >= PHASE1_THRESHOLD else 0,
        "url_flag": url_flag,
        "created_by": row["created_by"],
        "original_type": row["original_type"],
        "emotions": row["emotions"]
    }

    # Phase 2: RAG (Optional)
    # Note: AI service might fail if embeddings are unavailable.
    # We catch errors to allow the script to continue with Phase 1 results.
    ai_verdict = phase1.verdict
    ai_score = phase1.score
    ai_reasons = phase1.reasons
    top_similarity = 0.0
    avg_top3_similarity = 0.0
    num_neighbors = 0
    ontology_detected = False

    if use_rag:
        try:
            # Use redacted body for external calls (privacy-preserving).
            email_in = EmailIn(subject=subject, body=redacted_body, sender=sender, url=url_flag)

            # Convert Decision to ScanOut for compatibility with AI service
            scan_out = ScanOut(
                verdict=phase1.verdict,  # type: ignore
                score=phase1.score,
                reasons=phase1.reasons,
                indicators=phase1.indicators,
                redactions=RedactionsOut(
                    types=redaction_counts,
                    count=sum(redaction_counts.values())
                ),
                redacted_body=redacted_body
            )

            ai_out = analyze_email(
                payload=email_in,
                phase1=scan_out,
                neighbors_k=8,
                include_ontology_context=True
            )
            ai_verdict = ai_out.ai_verdict
            ai_score = ai_out.ai_score
            ai_reasons = ai_out.ai_reasons

            # Extract similarity metrics
            if ai_out.neighbors:
                num_neighbors = len(ai_out.neighbors)
                similarities = sorted([n.similarity for n in ai_out.neighbors], reverse=True)
                top_similarity = similarities[0] if similarities else 0.0
                avg_top3_similarity = sum(similarities[:3]) / min(3, len(similarities)) if similarities else 0.0

            # Check if ontology detected attacks
            if ai_out.ontology_attacks:
                ontology_detected = True

        except Exception as e:
            logging.error(f"RAG failed for row: {e}")
            # Fallback to Phase 1 is already set above

        result.update(
            {
                "rag_verdict": ai_verdict,
                "rag_score": ai_score,
                "rag_pred": 1 if ai_verdict != "benign" else 0,
                "top_similarity": top_similarity,
                "avg_top3_sim": avg_top3_similarity,
                "num_neighbors": num_neighbors,
                "ontology_fired": ontology_detected
            }
        )

    return result

def main(limit: int = 2000, use_rag: bool = True, split: str = None, use_tuned_thresholds: bool = False):
    repo_root = Path(__file__).resolve().parents[3]

    # Determine which file to load
    if split:
        dataset_path = repo_root / "datasets" / f"dataphish_{split}.jsonl"
        logger.info(f"Using {split} split")
    else:
        dataset_path = repo_root / "datasets" / "dataphish_2025.jsonl"
        logger.info(f"Using full dataset (no split)")

    if not dataset_path.exists():
        logger.error(f"Dataset not found at {dataset_path}")
        return

    # Load tuned thresholds if requested
    tuned_thresholds = None
    if use_tuned_thresholds:
        threshold_file = repo_root / "datasets" / "best_thresholds_dataphish.json"
        if threshold_file.exists():
            with open(threshold_file, 'r') as f:
                tuned_thresholds = json.load(f)
                logger.info(f"Loaded tuned thresholds: top_sim={tuned_thresholds['top_similarity_threshold']:.2f}, "
                           f"avg_top3={tuned_thresholds['avg_top3_threshold']:.2f}")
        else:
            logger.warning(f"Tuned thresholds file not found at {threshold_file}, using defaults")

    df = load_dataphish(dataset_path)
    logger.info(f"Loaded {len(df)} rows. Processing first {limit}...")
    
    df_subset = df.head(limit)
    results = []

    # Progress tracking
    start_time = time.time()
    last_report_time = start_time
    processed_count = 0

    # Process rows
    for idx, row in df_subset.iterrows():
        res = evaluate_row(row, use_rag=use_rag)
        results.append(res)
        processed_count += 1

        # Time-based progress reporting (every 60 seconds)
        current_time = time.time()
        if current_time - last_report_time >= 60:
            elapsed = current_time - start_time
            rate = processed_count / elapsed if elapsed > 0 else 0
            remaining = limit - processed_count
            eta_seconds = remaining / rate if rate > 0 else 0
            eta_minutes = eta_seconds / 60

            logger.info(
                f"PROGRESS: {processed_count}/{limit} ({processed_count*100/limit:.1f}%) | "
                f"Elapsed: {elapsed/60:.1f}min | Rate: {rate:.2f}/sec | "
                f"Remaining: {remaining} | ETA: {eta_minutes:.1f}min"
            )
            last_report_time = current_time

        # Also log every 50 rows as backup
        elif processed_count % 50 == 0:
            logger.info(f"Processed {processed_count}/{limit}")

    # Final timing summary
    total_time = time.time() - start_time
    logger.info(
        f"\n{'='*60}\n"
        f"COMPLETED: {processed_count} emails in {total_time/60:.2f} minutes\n"
        f"Average rate: {processed_count/total_time:.2f} emails/sec\n"
        f"{'='*60}"
    )

    res_df = pd.DataFrame(results)

    # Metrics Calculation
    def calc_metrics(sub_df, pred_col):
        tp = ((sub_df["label"] == 1) & (sub_df[pred_col] == 1)).sum()
        fp = ((sub_df["label"] == 0) & (sub_df[pred_col] == 1)).sum()
        fn = ((sub_df["label"] == 1) & (sub_df[pred_col] == 0)).sum()
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        return {"Precision": prec, "Recall": rec, "F1": f1, "Count": len(sub_df)}

    # Overall Metrics
    print("\n=== Overall Performance ===")
    print("Phase 1 (Rules):", calc_metrics(res_df, "phase1_pred"))
    if "rag_pred" in res_df.columns:
        print("Phase 2 (RAG):  ", calc_metrics(res_df, "rag_pred"))

        # RAG Similarity Analysis
        if "top_similarity" in res_df.columns:
            print("\n=== RAG Similarity Statistics ===")
            phish_df = res_df[res_df["label"] == 1]
            valid_df = res_df[res_df["label"] == 0]

            print(f"Phishing emails (n={len(phish_df)}):")
            print(f"  Top similarity - Mean: {phish_df['top_similarity'].mean():.4f}, "
                  f"Max: {phish_df['top_similarity'].max():.4f}, "
                  f"Median: {phish_df['top_similarity'].median():.4f}")
            print(f"  Avg top-3 sim - Mean: {phish_df['avg_top3_sim'].mean():.4f}, "
                  f"Max: {phish_df['avg_top3_sim'].max():.4f}")
            print(f"  Ontology fired: {phish_df['ontology_fired'].sum()} emails ({phish_df['ontology_fired'].sum()/len(phish_df)*100:.1f}%)")

            print(f"\nValid emails (n={len(valid_df)}):")
            print(f"  Top similarity - Mean: {valid_df['top_similarity'].mean():.4f}, "
                  f"Max: {valid_df['top_similarity'].max():.4f}")

            # Critical threshold analysis
            print(f"\n=== Threshold Analysis ===")
            print(f"Phishing with top_sim >= 0.70 (current threshold): {(phish_df['top_similarity'] >= 0.70).sum()}")
            print(f"Phishing with top_sim >= 0.60: {(phish_df['top_similarity'] >= 0.60).sum()}")
            print(f"Phishing with top_sim >= 0.50: {(phish_df['top_similarity'] >= 0.50).sum()}")
            print(f"Phishing with top_sim >= 0.40: {(phish_df['top_similarity'] >= 0.40).sum()}")
            print(f"Phishing with avg_top3 >= 0.68 (current threshold): {(phish_df['avg_top3_sim'] >= 0.68).sum()}")
            print(f"Phishing with avg_top3 >= 0.50: {(phish_df['avg_top3_sim'] >= 0.50).sum()}")
        
    # Breakdown by 'Created by' (Human vs LLM)
    print("\n=== Performance by Creator ===")
    for creator in res_df["created_by"].unique():
        sub = res_df[res_df["created_by"] == creator]
        print(f"\nCreator: {creator}")
        print("Phase 1:", calc_metrics(sub, "phase1_pred"))
        if "rag_pred" in res_df.columns:
            print("Phase 2:", calc_metrics(sub, "rag_pred"))

    # Breakdown by 'Emotion'
    print("\n=== Performance by Emotion ===")
    # Flatten all emotion lists to find unique tags
    all_emotions = set()
    for em_list in res_df["emotions"]:
        for em in em_list:
            all_emotions.add(em)
            
    for emotion in sorted(all_emotions):
        # Filter rows where this emotion is present in the list
        sub = res_df[res_df["emotions"].apply(lambda x: emotion in x)]
        if len(sub) > 0:
            print(f"\nEmotion: {emotion}")
            print("Phase 1:", calc_metrics(sub, "phase1_pred"))
            if "rag_pred" in res_df.columns:
                print("Phase 2:", calc_metrics(sub, "rag_pred"))

    # Save results
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = repo_root / "datasets" / f"eval_dataphish_{ts}.csv"
    res_df.to_csv(out_file, index=False)
    logger.info(f"Saved detailed results to {out_file}")

    # Final diagnostic summary
    if "top_similarity" in res_df.columns:
        phish_df = res_df[res_df["label"] == 1]
        print("\n" + "="*70)
        print("DIAGNOSTIC SUMMARY")
        print("="*70)

        low_sim_phish = (phish_df['top_similarity'] < 0.50).sum()
        print(f"⚠️  {low_sim_phish}/{len(phish_df)} phishing emails have top_sim < 0.50")
        print(f"   This explains why RAG isn't improving recall!")

        if low_sim_phish / len(phish_df) > 0.7:
            print("\n💡 RECOMMENDATION:")
            print("   - DataPhish 2025 (AI-generated) is too different from training corpus")
            print("   - Consider lowering thresholds OR retraining on 2025 data")
            print("   - Current thresholds (0.70/0.68) were tuned for SpamAssassin/Nazario")

        print(f"\n📊 Files saved:")
        print(f"   CSV: {out_file}")
        print("="*70)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate CyberCane on DataPhish 2025 dataset")
    parser.add_argument("--limit", type=int, default=2000, help="Number of rows to process")
    parser.add_argument("--no-rag", action="store_true", help="Disable RAG analysis")
    parser.add_argument("--split", choices=["train", "val", "test"], default=None,
                        help="Use specific data split (train/val/test)")
    parser.add_argument("--use-tuned-thresholds", action="store_true",
                        help="Use thresholds from best_thresholds_dataphish.json")
    args = parser.parse_args()

    main(limit=args.limit, use_rag=not args.no_rag, split=args.split, use_tuned_thresholds=args.use_tuned_thresholds)
