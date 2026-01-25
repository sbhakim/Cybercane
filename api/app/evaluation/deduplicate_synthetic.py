"""
Deduplication for synthetic phishing dataset.

Implements two-stage filtering:
1. Exact duplicate removal (by hash)
2. Near-duplicate removal (TF-IDF cosine similarity)

Outputs:
- Deduplicated CSV
- Deduplication report (JSON)
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np


def compute_content_hash(row: pd.Series) -> str:
    """Compute hash for exact duplicate detection."""
    content = f"{row['subject']}||{row['body']}"
    return hashlib.sha256(content.encode()).hexdigest()


def find_exact_duplicates(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, int]]:
    """
    Remove exact duplicates based on subject+body hash.

    Returns (deduplicated_df, stats_dict)
    """
    print("\n[Stage 1: Exact Duplicate Removal]")

    # Compute hashes
    if "sample_hash" not in df.columns:
        df["sample_hash"] = df.apply(compute_content_hash, axis=1)

    # Find duplicates
    initial_count = len(df)
    df_dedup = df.drop_duplicates(subset=["sample_hash"], keep="first")
    removed_count = initial_count - len(df_dedup)

    print(f"  Initial samples: {initial_count}")
    print(f"  Exact duplicates removed: {removed_count}")
    print(f"  Remaining: {len(df_dedup)}")

    stats = {
        "initial_count": initial_count,
        "exact_duplicates_removed": removed_count,
        "remaining_after_exact": len(df_dedup),
    }

    return df_dedup, stats


def find_near_duplicates(
    df: pd.DataFrame,
    threshold: float = 0.85,
    ngram_range: Tuple[int, int] = (1, 3)
) -> Tuple[pd.DataFrame, Dict[str, any]]:
    """
    Remove near-duplicates using TF-IDF cosine similarity.

    Algorithm:
    1. Compute TF-IDF vectors for email bodies
    2. Compute pairwise cosine similarity
    3. For each pair above threshold, keep first occurrence
    4. Return deduplicated dataframe

    Args:
        df: Input dataframe
        threshold: Similarity threshold (0.0-1.0), default 0.85
        ngram_range: N-gram range for TF-IDF

    Returns:
        (deduplicated_df, stats_dict)
    """
    print(f"\n[Stage 2: Near-Duplicate Removal (threshold={threshold})]")

    if len(df) < 2:
        print("  Skipping: <2 samples")
        return df, {"near_duplicates_removed": 0}

    # Vectorize
    print("  Computing TF-IDF vectors...")
    vectorizer = TfidfVectorizer(
        ngram_range=ngram_range,
        max_features=5000,
        stop_words="english",
        lowercase=True,
    )

    try:
        tfidf_matrix = vectorizer.fit_transform(df["body"].fillna(""))
    except Exception as e:
        print(f"  ✗ TF-IDF failed: {e}")
        return df, {"near_duplicates_removed": 0, "error": str(e)}

    # Compute pairwise similarity
    print("  Computing pairwise similarity...")
    similarity_matrix = cosine_similarity(tfidf_matrix)

    # Find near-duplicates (upper triangle, excluding diagonal)
    n = len(df)
    to_remove: Set[int] = set()
    duplicate_pairs: List[Tuple[int, int, float]] = []

    for i in range(n):
        if i in to_remove:
            continue
        for j in range(i + 1, n):
            if j in to_remove:
                continue
            sim = similarity_matrix[i, j]
            if sim >= threshold:
                to_remove.add(j)  # Keep first occurrence (i), remove second (j)
                duplicate_pairs.append((i, j, sim))

    # Remove duplicates
    keep_indices = [i for i in range(n) if i not in to_remove]
    df_dedup = df.iloc[keep_indices].reset_index(drop=True)

    print(f"  Near-duplicate pairs found: {len(duplicate_pairs)}")
    print(f"  Samples removed: {len(to_remove)}")
    print(f"  Remaining: {len(df_dedup)}")

    # Detailed stats
    if duplicate_pairs:
        similarities = [sim for _, _, sim in duplicate_pairs]
        print(f"  Similarity range: {min(similarities):.3f} - {max(similarities):.3f}")
        print(f"  Mean similarity: {np.mean(similarities):.3f}")

        # Show examples
        print("\n  Example near-duplicate pairs:")
        for idx, (i, j, sim) in enumerate(duplicate_pairs[:3]):
            print(f"    Pair {idx+1} (similarity={sim:.3f}):")
            print(f"      [{i}] {df.iloc[i]['subject'][:60]}...")
            print(f"      [{j}] {df.iloc[j]['subject'][:60]}...")

    stats = {
        "near_duplicates_removed": len(to_remove),
        "duplicate_pairs": len(duplicate_pairs),
        "threshold": threshold,
        "similarity_stats": {
            "min": float(min(similarities)) if similarities else 0.0,
            "max": float(max(similarities)) if similarities else 0.0,
            "mean": float(np.mean(similarities)) if similarities else 0.0,
        } if duplicate_pairs else {},
    }

    return df_dedup, stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Deduplicate synthetic phishing dataset")
    parser.add_argument(
        "--input",
        required=True,
        help="Input CSV path"
    )
    parser.add_argument(
        "--output",
        help="Output CSV path (default: <input>_dedup.csv)"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.85,
        help="Near-duplicate similarity threshold (default: 0.85)"
    )
    parser.add_argument(
        "--report",
        help="Deduplication report JSON path (default: <output>_report.json)"
    )
    args = parser.parse_args()

    # Determine paths
    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.parent / f"{input_path.stem}_dedup.csv"

    if args.report:
        report_path = Path(args.report)
    else:
        report_path = output_path.parent / f"{output_path.stem}_report.json"

    print(f"Input: {input_path}")
    print(f"Output: {output_path}")
    print(f"Report: {report_path}")

    # Load data
    df = pd.read_csv(input_path)
    print(f"\nLoaded {len(df)} samples from {input_path}")

    # Stage 1: Exact duplicates
    df_dedup, exact_stats = find_exact_duplicates(df)

    # Stage 2: Near-duplicates
    df_final, near_stats = find_near_duplicates(df_dedup, threshold=args.threshold)

    # Save deduplicated data
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_final.to_csv(output_path, index=False)
    print(f"\n✓ Saved {len(df_final)} deduplicated samples to {output_path}")

    # Generate report
    report = {
        "input_file": str(input_path),
        "output_file": str(output_path),
        "deduplication_threshold": args.threshold,
        "summary": {
            "initial_samples": len(df),
            "exact_duplicates_removed": exact_stats["exact_duplicates_removed"],
            "near_duplicates_removed": near_stats["near_duplicates_removed"],
            "final_samples": len(df_final),
            "total_removed": len(df) - len(df_final),
            "retention_rate": len(df_final) / len(df) if len(df) > 0 else 0.0,
        },
        "exact_dedup_stats": exact_stats,
        "near_dedup_stats": near_stats,
    }

    # Per-category breakdown
    if "category" in df_final.columns:
        category_dist = df_final["category"].value_counts().to_dict()
        report["category_distribution"] = category_dist
        print(f"\n📊 Category distribution after deduplication:")
        for cat, count in sorted(category_dist.items()):
            print(f"  {cat}: {count}")

    # Per-model breakdown
    if "gen_model" in df_final.columns:
        model_dist = df_final["gen_model"].value_counts().to_dict()
        report["model_distribution"] = model_dist
        print(f"\n🤖 Model distribution after deduplication:")
        for model, count in sorted(model_dist.items()):
            print(f"  {model}: {count}")

    # Save report
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n✓ Saved deduplication report to {report_path}")

    # Summary
    print(f"\n{'='*80}")
    print(f"DEDUPLICATION SUMMARY")
    print(f"{'='*80}")
    print(f"Initial samples:        {len(df)}")
    print(f"Exact duplicates:       -{exact_stats['exact_duplicates_removed']}")
    print(f"Near duplicates:        -{near_stats['near_duplicates_removed']}")
    print(f"{'─'*80}")
    print(f"Final samples:          {len(df_final)}")
    print(f"Retention rate:         {len(df_final)/len(df)*100:.1f}%")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()
