"""
Contamination checker for synthetic phishing dataset.

Verifies that synthetic samples do not overlap with train/val/test corpora
using embedding-based similarity.

Outputs:
- Contamination report (JSON)
- Filtered dataset (CSV) with contaminated samples removed
- Contamination details (CSV) showing flagged samples
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
import numpy as np
from tqdm import tqdm


def get_openai_embedding(text: str, model: str = "text-embedding-3-small") -> List[float]:
    """Get OpenAI embedding for text."""
    from openai import OpenAI

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.embeddings.create(
        model=model,
        input=text.strip()[:8000]  # Truncate to avoid token limits
    )
    return response.data[0].embedding


def batch_embed(
    texts: List[str],
    model: str = "text-embedding-3-small",
    batch_size: int = 100
) -> np.ndarray:
    """
    Embed texts in batches.

    Returns: numpy array of shape (n_texts, embedding_dim)
    """
    embeddings = []

    print(f"  Embedding {len(texts)} texts in batches of {batch_size}...")
    for i in tqdm(range(0, len(texts), batch_size), desc="  Batches"):
        batch = texts[i:i + batch_size]
        try:
            batch_embs = [get_openai_embedding(text, model) for text in batch]
            embeddings.extend(batch_embs)
        except Exception as e:
            print(f"    Error embedding batch {i//batch_size}: {e}")
            # Retry individually
            for text in batch:
                try:
                    emb = get_openai_embedding(text, model)
                    embeddings.append(emb)
                except Exception as e2:
                    print(f"    Error embedding individual sample: {e2}")
                    # Use zero vector as fallback
                    embeddings.append([0.0] * 1536)

    return np.array(embeddings)


def cosine_similarity_matrix(
    embeddings_a: np.ndarray,
    embeddings_b: np.ndarray
) -> np.ndarray:
    """
    Compute cosine similarity between two sets of embeddings.

    Returns: similarity matrix of shape (len(a), len(b))
    """
    # Normalize
    a_norm = embeddings_a / (np.linalg.norm(embeddings_a, axis=1, keepdims=True) + 1e-8)
    b_norm = embeddings_b / (np.linalg.norm(embeddings_b, axis=1, keepdims=True) + 1e-8)

    # Compute similarity
    similarity = np.dot(a_norm, b_norm.T)
    return similarity


def check_contamination(
    synthetic_df: pd.DataFrame,
    corpus_df: pd.DataFrame,
    threshold: float = 0.90,
    model: str = "text-embedding-3-small"
) -> Tuple[List[int], Dict[str, any]]:
    """
    Check for contamination between synthetic and corpus.

    Args:
        synthetic_df: Synthetic phishing samples
        corpus_df: Real corpus (train/val/test)
        threshold: Similarity threshold for contamination
        model: Embedding model name

    Returns:
        (contaminated_indices, stats_dict)
    """
    print(f"\n  Checking against corpus ({len(corpus_df)} samples)...")

    # Combine subject + body for both datasets
    synthetic_texts = (
        synthetic_df["subject"].fillna("") + " " + synthetic_df["body"].fillna("")
    ).tolist()

    corpus_texts = (
        corpus_df["subject"].fillna("") + " " + corpus_df["body"].fillna("")
    ).tolist()

    # Embed both
    print(f"  Embedding synthetic samples...")
    synthetic_embeddings = batch_embed(synthetic_texts, model=model)

    print(f"  Embedding corpus samples...")
    corpus_embeddings = batch_embed(corpus_texts, model=model)

    # Compute similarity
    print(f"  Computing similarity matrix...")
    similarity = cosine_similarity_matrix(synthetic_embeddings, corpus_embeddings)

    # Find contamination
    max_similarities = similarity.max(axis=1)  # Max similarity for each synthetic sample
    contaminated_mask = max_similarities >= threshold
    contaminated_indices = np.where(contaminated_mask)[0].tolist()

    # Stats
    stats = {
        "threshold": threshold,
        "synthetic_count": len(synthetic_df),
        "corpus_count": len(corpus_df),
        "contaminated_count": len(contaminated_indices),
        "contamination_rate": len(contaminated_indices) / len(synthetic_df) if len(synthetic_df) > 0 else 0.0,
        "similarity_stats": {
            "min": float(max_similarities.min()),
            "max": float(max_similarities.max()),
            "mean": float(max_similarities.mean()),
            "median": float(np.median(max_similarities)),
            "p95": float(np.percentile(max_similarities, 95)),
            "p99": float(np.percentile(max_similarities, 99)),
        },
    }

    print(f"  Contaminated samples: {len(contaminated_indices)}/{len(synthetic_df)} ({stats['contamination_rate']*100:.2f}%)")
    print(f"  Similarity stats: min={stats['similarity_stats']['min']:.3f}, max={stats['similarity_stats']['max']:.3f}, mean={stats['similarity_stats']['mean']:.3f}")

    # Return contaminated indices with match details
    contamination_details = []
    for idx in contaminated_indices:
        max_sim = max_similarities[idx]
        match_idx = similarity[idx].argmax()
        contamination_details.append({
            "synthetic_idx": int(idx),
            "synthetic_id": synthetic_df.iloc[idx].get("id", f"sample_{idx}"),
            "synthetic_category": synthetic_df.iloc[idx].get("category", "unknown"),
            "similarity": float(max_sim),
            "match_corpus_idx": int(match_idx),
            "match_subject": corpus_df.iloc[match_idx].get("subject", "")[:100],
        })

    stats["contamination_details"] = contamination_details

    return contaminated_indices, stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Check contamination in synthetic dataset")
    parser.add_argument(
        "--input",
        required=True,
        help="Input synthetic CSV path"
    )
    parser.add_argument(
        "--corpora",
        nargs="+",
        required=True,
        help="Real corpus CSV paths (train, val, test)"
    )
    parser.add_argument(
        "--output",
        help="Output cleaned CSV path (default: <input>_clean.csv)"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.90,
        help="Contamination similarity threshold (default: 0.90)"
    )
    parser.add_argument(
        "--report",
        help="Contamination report JSON path (default: <output>_contamination_report.json)"
    )
    parser.add_argument(
        "--flagged",
        help="CSV of flagged samples (default: <output>_contaminated.csv)"
    )
    parser.add_argument(
        "--model",
        default="text-embedding-3-small",
        help="Embedding model (default: text-embedding-3-small)"
    )
    args = parser.parse_args()

    # Determine paths
    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    output_path = Path(args.output) if args.output else input_path.parent / f"{input_path.stem}_clean.csv"
    report_path = Path(args.report) if args.report else output_path.parent / f"{output_path.stem}_contamination_report.json"
    flagged_path = Path(args.flagged) if args.flagged else output_path.parent / f"{output_path.stem}_contaminated.csv"

    print(f"{'='*80}")
    print(f"CONTAMINATION CHECK")
    print(f"{'='*80}")
    print(f"Input: {input_path}")
    print(f"Threshold: {args.threshold}")
    print(f"Model: {args.model}")
    print(f"Corpora: {len(args.corpora)} files")
    for corpus in args.corpora:
        print(f"  - {corpus}")

    # Load synthetic data
    synthetic_df = pd.read_csv(input_path)
    print(f"\nLoaded {len(synthetic_df)} synthetic samples")

    # Load corpora
    print(f"\nLoading corpora...")
    corpus_dfs = []
    for corpus_path in args.corpora:
        if not Path(corpus_path).exists():
            print(f"  ⚠  Corpus not found: {corpus_path} (skipping)")
            continue
        try:
            corpus_df = pd.read_csv(corpus_path)
            corpus_dfs.append(corpus_df)
            print(f"  ✓ Loaded {len(corpus_df)} samples from {Path(corpus_path).name}")
        except Exception as e:
            print(f"  ✗ Error loading {corpus_path}: {e}")

    if not corpus_dfs:
        print("\n✗ No valid corpora loaded. Exiting.")
        return

    # Combine all corpora
    combined_corpus = pd.concat(corpus_dfs, ignore_index=True)
    print(f"\nCombined corpus: {len(combined_corpus)} samples")

    # Check contamination
    print(f"\n{'='*80}")
    print(f"Running contamination check (threshold={args.threshold})...")
    print(f"{'='*80}")

    contaminated_indices, stats = check_contamination(
        synthetic_df,
        combined_corpus,
        threshold=args.threshold,
        model=args.model
    )

    # Filter clean samples
    clean_df = synthetic_df.drop(contaminated_indices).reset_index(drop=True)
    contaminated_df = synthetic_df.iloc[contaminated_indices].reset_index(drop=True)

    # Save outputs
    output_path.parent.mkdir(parents=True, exist_ok=True)
    clean_df.to_csv(output_path, index=False)
    print(f"\n✓ Saved {len(clean_df)} clean samples to {output_path}")

    if len(contaminated_df) > 0:
        contaminated_df.to_csv(flagged_path, index=False)
        print(f"✓ Saved {len(contaminated_df)} contaminated samples to {flagged_path}")

    # Generate report
    report = {
        "input_file": str(input_path),
        "output_file": str(output_path),
        "corpora_files": args.corpora,
        "threshold": args.threshold,
        "embedding_model": args.model,
        "summary": {
            "initial_samples": len(synthetic_df),
            "contaminated_samples": len(contaminated_indices),
            "clean_samples": len(clean_df),
            "contamination_rate": stats["contamination_rate"],
        },
        "statistics": stats,
    }

    # Per-category contamination
    if "category" in clean_df.columns:
        category_dist = clean_df["category"].value_counts().to_dict()
        report["category_distribution_clean"] = category_dist

    # Per-model contamination
    if "gen_model" in clean_df.columns:
        model_dist = clean_df["gen_model"].value_counts().to_dict()
        report["model_distribution_clean"] = model_dist

    # Save report
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"✓ Saved contamination report to {report_path}")

    # Summary
    print(f"\n{'='*80}")
    print(f"CONTAMINATION SUMMARY")
    print(f"{'='*80}")
    print(f"Initial samples:        {len(synthetic_df)}")
    print(f"Contaminated (>{args.threshold}): -{len(contaminated_indices)}")
    print(f"{'─'*80}")
    print(f"Clean samples:          {len(clean_df)}")
    print(f"Contamination rate:     {stats['contamination_rate']*100:.2f}%")
    print(f"\nSimilarity distribution:")
    print(f"  Min:    {stats['similarity_stats']['min']:.4f}")
    print(f"  Mean:   {stats['similarity_stats']['mean']:.4f}")
    print(f"  Median: {stats['similarity_stats']['median']:.4f}")
    print(f"  P95:    {stats['similarity_stats']['p95']:.4f}")
    print(f"  P99:    {stats['similarity_stats']['p99']:.4f}")
    print(f"  Max:    {stats['similarity_stats']['max']:.4f}")
    print(f"{'='*80}")

    if stats['contamination_details']:
        print(f"\n⚠  Contaminated samples (top 5):")
        for detail in stats['contamination_details'][:5]:
            print(f"  [{detail['synthetic_id']}] similarity={detail['similarity']:.4f}")
            print(f"    Matched: {detail['match_subject']}")


if __name__ == "__main__":
    main()
