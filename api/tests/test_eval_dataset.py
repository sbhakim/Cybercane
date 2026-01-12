from pathlib import Path

from app.evaluation.pandas_eval import evaluate_pipeline, load_dataset


def test_evaluate_on_dataset_subset():
    base = Path(__file__).resolve().parents[2]
    csv_path = base / "datasets" / "Nazario.csv"
    if not csv_path.exists():
        return

    df = load_dataset(csv_path)
    out_df, summary = evaluate_pipeline(df, limit=100, enable_dns_checks=False)

    assert summary.processed_rows >= 1
    m = summary.metrics
    assert 0.0 <= m["accuracy"] <= 1.0
    assert 0.0 <= m["precision"] <= 1.0
    assert 0.0 <= m["recall"] <= 1.0
    assert 0.0 <= m["f1"] <= 1.0


