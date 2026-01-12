from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List

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

    out_dir = Path("reports") / f"baselines_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    tab_dir = out_dir / "tables"
    tab_dir.mkdir(parents=True, exist_ok=True)
    out_df = pd.DataFrame([r.__dict__ for r in rows])
    out_df.to_csv(tab_dir / "baseline_metrics.csv", index=False)

    print(str(out_dir))


if __name__ == "__main__":
    main()
