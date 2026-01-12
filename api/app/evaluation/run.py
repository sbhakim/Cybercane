"""
Evaluation runner:
- Computes dataset stats (pandas) for Nazario dataset
- Runs the deterministic pipeline on all rows
- Saves detailed outputs (CSV + JSON) under datasets/evaluation_results_[timestamp]

Run from repo root:
    py -m app.evaluation.run | cat
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .pandas_eval import compute_dataset_stats, evaluate_pipeline, load_dataset, write_outputs


def _datasets_dir() -> Path:
    # repo_root/datasets
    return Path(__file__).resolve().parents[3] / "datasets"


def _dataset_path(name: str) -> Path:
    return _datasets_dir() / name


def main(dataset_filename: str = "Nazario.csv", limit: Optional[int] = None, threshold: int = 2) -> None:
    csv_path = _dataset_path(dataset_filename)
    if not csv_path.exists():
        print(f"Dataset not found: {csv_path}")
        return

    df = load_dataset(csv_path)
    stats = compute_dataset_stats(df)
    eval_df, summary = evaluate_pipeline(df, limit=limit, enable_dns_checks=False, threshold=threshold)
    out_dir = write_outputs(
        base_datasets_dir=_datasets_dir(),
        dataset_name=Path(dataset_filename).stem,
        dataset_stats=stats,
        eval_df=eval_df,
        summary=summary,
    )
    print(f"Wrote evaluation results to: {out_dir}")


if __name__ == "__main__":
    main()


