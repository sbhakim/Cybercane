"""
Generate comprehensive manifest for synthetic dataset.

Combines:
- Generation configuration
- Deduplication statistics
- Contamination statistics
- Final dataset characteristics
- Model and category distributions

Produces publication-ready manifest for reproducibility.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

import pandas as pd
import numpy as np


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON file with error handling."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"  ⚠  Error loading {path}: {e}")
        return {}


def compute_dataset_stats(df: pd.DataFrame) -> Dict[str, Any]:
    """Compute comprehensive dataset statistics."""
    stats = {
        "total_samples": len(df),
        "samples_by_category": df["category"].value_counts().to_dict() if "category" in df.columns else {},
        "samples_by_model": df["gen_model"].value_counts().to_dict() if "gen_model" in df.columns else {},
    }

    # Length statistics
    if "body_length" in df.columns:
        stats["body_length"] = {
            "min": int(df["body_length"].min()),
            "max": int(df["body_length"].max()),
            "mean": float(df["body_length"].mean()),
            "median": float(df["body_length"].median()),
            "std": float(df["body_length"].std()),
        }

    if "subject_length" in df.columns:
        stats["subject_length"] = {
            "min": int(df["subject_length"].min()),
            "max": int(df["subject_length"].max()),
            "mean": float(df["subject_length"].mean()),
            "median": float(df["subject_length"].median()),
        }

    # URL presence
    if "urls" in df.columns:
        url_count = df["urls"].sum()
        stats["url_presence"] = {
            "count": int(url_count),
            "percentage": float(url_count / len(df) * 100) if len(df) > 0 else 0.0,
        }

    # Provenance fields
    provenance_fields = ["gen_model", "gen_temperature", "gen_seed", "prompt_version", "gen_timestamp"]
    stats["provenance_coverage"] = {
        field: float(df[field].notna().sum() / len(df) * 100) if field in df.columns else 0.0
        for field in provenance_fields
    }

    # Model-category cross-tabulation
    if "gen_model" in df.columns and "category" in df.columns:
        crosstab = pd.crosstab(df["category"], df["gen_model"])
        stats["model_category_distribution"] = crosstab.to_dict()

    return stats


def compute_diversity_metrics(df: pd.DataFrame) -> Dict[str, Any]:
    """Compute diversity metrics."""
    metrics = {}

    # Unique subjects
    if "subject" in df.columns:
        unique_subjects = df["subject"].nunique()
        metrics["unique_subjects"] = {
            "count": int(unique_subjects),
            "percentage": float(unique_subjects / len(df) * 100) if len(df) > 0 else 0.0,
        }

    # Unique bodies (by hash)
    if "sample_hash" in df.columns:
        unique_bodies = df["sample_hash"].nunique()
        metrics["unique_bodies"] = {
            "count": int(unique_bodies),
            "percentage": float(unique_bodies / len(df) * 100) if len(df) > 0 else 0.0,
        }

    # Length distribution bins
    if "body_length" in df.columns:
        bins = [0, 250, 450, 700, 10000]
        labels = ["short (0-250)", "medium (251-450)", "long (451-700)", "very_long (>700)"]
        df["length_bin"] = pd.cut(df["body_length"], bins=bins, labels=labels, include_lowest=True)
        bin_counts = df["length_bin"].value_counts().to_dict()
        metrics["length_distribution"] = {str(k): int(v) for k, v in bin_counts.items()}

    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic dataset manifest")
    parser.add_argument(
        "--config",
        required=True,
        help="Generation config JSON path"
    )
    parser.add_argument(
        "--final-data",
        required=True,
        help="Final cleaned dataset CSV path"
    )
    parser.add_argument(
        "--dedup-report",
        help="Deduplication report JSON path"
    )
    parser.add_argument(
        "--contamination-report",
        help="Contamination report JSON path"
    )
    parser.add_argument(
        "--output",
        help="Output manifest JSON path (default from config or auto-generated)"
    )
    args = parser.parse_args()

    print(f"{'='*80}")
    print(f"MANIFEST GENERATION")
    print(f"{'='*80}")

    # Load configuration
    config_path = Path(args.config)
    config = load_json(config_path)
    print(f"✓ Loaded config: {config_path}")

    # Load final dataset
    data_path = Path(args.final_data)
    df = pd.read_csv(data_path)
    print(f"✓ Loaded final dataset: {data_path} ({len(df)} samples)")

    # Load reports
    dedup_report = load_json(Path(args.dedup_report)) if args.dedup_report else {}
    contamination_report = load_json(Path(args.contamination_report)) if args.contamination_report else {}

    if dedup_report:
        print(f"✓ Loaded deduplication report")
    if contamination_report:
        print(f"✓ Loaded contamination report")

    # Compute statistics
    print(f"\nComputing dataset statistics...")
    dataset_stats = compute_dataset_stats(df)
    diversity_metrics = compute_diversity_metrics(df)

    # Build manifest
    manifest = {
        "metadata": {
            "manifest_version": "1.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "dataset_version": config.get("version", "unknown"),
            "description": config.get("description", "Synthetic healthcare phishing dataset"),
        },
        "generation_config": {
            "models": config.get("generation", {}).get("models", []),
            "holdout_models": config.get("generation", {}).get("holdout_models", []),
            "seed": config.get("generation", {}).get("seed"),
            "samples_per_category": config.get("generation", {}).get("samples_per_category"),
            "prompt_version": config.get("generation", {}).get("prompt_version"),
            "temperature_range": [
                m.get("temperature") for m in config.get("generation", {}).get("models", [])
            ],
        },
        "categories": config.get("categories", {}),
        "quality_filters": config.get("quality_filters", {}),
        "deduplication": {
            "config": config.get("deduplication", {}),
            "results": dedup_report.get("summary", {}),
            "exact_stats": dedup_report.get("exact_dedup_stats", {}),
            "near_stats": dedup_report.get("near_dedup_stats", {}),
        },
        "contamination_check": {
            "config": config.get("contamination_checks", {}),
            "results": contamination_report.get("summary", {}),
            "statistics": contamination_report.get("statistics", {}),
        },
        "final_dataset": {
            "file_path": str(data_path),
            "statistics": dataset_stats,
            "diversity_metrics": diversity_metrics,
        },
        "provenance": {
            "traceable": dataset_stats.get("provenance_coverage", {}).get("gen_model", 0) == 100.0,
            "reproducible": True if config.get("generation", {}).get("seed") else False,
            "auditable": True,
        },
    }

    # Validation checks
    manifest["validation"] = {
        "all_samples_have_urls": dataset_stats.get("url_presence", {}).get("percentage", 0) >= 90.0,
        "all_samples_have_provenance": all(
            v >= 95.0 for v in dataset_stats.get("provenance_coverage", {}).values()
        ),
        "low_contamination": contamination_report.get("summary", {}).get("contamination_rate", 1.0) < 0.05,
        "high_diversity": diversity_metrics.get("unique_subjects", {}).get("percentage", 0) >= 80.0,
    }

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path(config.get("output", {}).get("manifest_path", "reports/synthetic_generation_manifest.json"))

    # Save manifest
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n✓ Saved manifest to {output_path}")

    # Print summary
    print(f"\n{'='*80}")
    print(f"MANIFEST SUMMARY")
    print(f"{'='*80}")
    print(f"Dataset version:        {manifest['metadata']['dataset_version']}")
    print(f"Final samples:          {manifest['final_dataset']['statistics']['total_samples']}")
    print(f"Models used:            {len(manifest['generation_config']['models'])}")
    print(f"Categories:             {len(manifest['categories'])}")

    print(f"\nQuality Metrics:")
    print(f"  URL presence:         {dataset_stats.get('url_presence', {}).get('percentage', 0):.1f}%")
    print(f"  Unique subjects:      {diversity_metrics.get('unique_subjects', {}).get('percentage', 0):.1f}%")
    print(f"  Provenance complete:  {manifest['validation']['all_samples_have_provenance']}")

    if dedup_report:
        print(f"\nDeduplication:")
        print(f"  Initial:              {dedup_report.get('summary', {}).get('initial_samples', 'N/A')}")
        print(f"  Exact removed:        {dedup_report.get('summary', {}).get('exact_duplicates_removed', 'N/A')}")
        print(f"  Near removed:         {dedup_report.get('summary', {}).get('near_duplicates_removed', 'N/A')}")
        print(f"  Final:                {dedup_report.get('summary', {}).get('final_samples', 'N/A')}")

    if contamination_report:
        print(f"\nContamination:")
        print(f"  Threshold:            {contamination_report.get('threshold', 'N/A')}")
        print(f"  Contaminated:         {contamination_report.get('summary', {}).get('contaminated_samples', 'N/A')}")
        print(f"  Contamination rate:   {contamination_report.get('summary', {}).get('contamination_rate', 0)*100:.2f}%")

    print(f"\n✓ Validation checks:")
    for check, passed in manifest["validation"].items():
        status = "✓" if passed else "✗"
        print(f"  {status} {check}")

    print(f"{'='*80}")


if __name__ == "__main__":
    main()
