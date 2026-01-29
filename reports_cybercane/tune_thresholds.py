from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact


TUNED_RULE_WEIGHTS = {
    "freemail_brand_claim": 3,
    "lookalike_domain": 3,
    "ip_literal_link": 3,
    "url_present": 1,
    "shortened_url": 2,
    "urgency": 2,
    "creds_request": 3,
    "missing_mx": 2,
    "no_spf": 2,
    "no_dmarc": 1,
    "strict_dmarc_missing_align": 3,
}


@dataclass
class Metrics:
    threshold: int
    tp: int
    tn: int
    fp: int
    fn: int
    accuracy: float
    precision: float
    recall: float
    f1: float


def _score_dataset(df: pd.DataFrame, rule_weights: dict[str, int] | None) -> pd.DataFrame:
    scores = []
    labels = []

    for row in df.itertuples(index=False):
        sender = getattr(row, "sender_email", None) or getattr(row, "sender", "") or ""
        subject = getattr(row, "subject", "") or ""
        body = getattr(row, "body", "") or ""
        url_flag = int(getattr(row, "urls", 0) or 0)
        label = int(getattr(row, "label", 0) or 0)

        redacted_body, _ = redact(str(body))
        decision = score_email(
            sender=str(sender),
            subject=str(subject),
            body=redacted_body,
            url_flag=url_flag,
            enable_dns_checks=False,
            rule_weights=rule_weights,
        )

        scores.append(int(decision.score))
        labels.append(label)

    return pd.DataFrame({"score": scores, "label": labels})


def _metrics_for_threshold(scores: np.ndarray, labels: np.ndarray, threshold: int) -> Metrics:
    pred = scores >= threshold
    tp = int(((labels == 1) & pred).sum())
    tn = int(((labels == 0) & ~pred).sum())
    fp = int(((labels == 0) & pred).sum())
    fn = int(((labels == 1) & ~pred).sum())
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    return Metrics(threshold, tp, tn, fp, fn, accuracy, precision, recall, f1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Tune deterministic threshold on validation data")
    parser.add_argument("--tuned", action="store_true", help="Use tuned rule weights")
    args = parser.parse_args()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = "tuned" if args.tuned else "baseline"
    run_dir = Path("reports") / f"threshold_tuning_{suffix}_{ts}"
    fig_dir = run_dir / "figures"
    tab_dir = run_dir / "tables"
    fig_dir.mkdir(parents=True, exist_ok=True)
    tab_dir.mkdir(parents=True, exist_ok=True)

    val_df = pd.read_csv("reports/combined_eval_split_val.csv")
    test_df = pd.read_csv("reports/combined_eval_split_test.csv")

    rule_weights = TUNED_RULE_WEIGHTS if args.tuned else None
    val_scores = _score_dataset(val_df, rule_weights)
    test_scores = _score_dataset(test_df, rule_weights)

    max_score = int(max(val_scores["score"].max(), test_scores["score"].max()))
    thresholds = list(range(0, max_score + 1))

    val_metrics = [
        _metrics_for_threshold(val_scores["score"].to_numpy(), val_scores["label"].to_numpy(), t)
        for t in thresholds
    ]

    metrics_df = pd.DataFrame([m.__dict__ for m in val_metrics])
    metrics_df.to_csv(tab_dir / "val_threshold_metrics.csv", index=False)

    # Pick best threshold by F1, tie-breaker: lower threshold.
    best_row = metrics_df.sort_values(["f1", "threshold"], ascending=[False, True]).iloc[0]
    best_threshold = int(best_row["threshold"])

    # Evaluate on test with best threshold
    test_metric = _metrics_for_threshold(
        test_scores["score"].to_numpy(),
        test_scores["label"].to_numpy(),
        best_threshold,
    )
    pd.DataFrame([test_metric.__dict__]).to_csv(tab_dir / "test_metrics_best_threshold.csv", index=False)

    # Plots
    plt.rcParams.update({"figure.dpi": 300, "font.size": 10})

    def _save(fig, name: str) -> None:
        fig.savefig(fig_dir / f"{name}.png", dpi=300, bbox_inches="tight")
        fig.savefig(fig_dir / f"{name}.pdf", bbox_inches="tight")
        plt.close(fig)

    fig, ax = plt.subplots()
    ax.plot(metrics_df["threshold"], metrics_df["f1"], label="F1", color="#1f78b4")
    ax.set_title("Validation F1 vs Threshold")
    ax.set_xlabel("Threshold")
    ax.set_ylabel("F1")
    ax.axvline(best_threshold, color="#e31a1c", linestyle="--", label=f"best={best_threshold}")
    ax.legend()
    _save(fig, "val_f1_curve")

    fig, ax = plt.subplots()
    ax.plot(metrics_df["threshold"], metrics_df["precision"], label="Precision", color="#33a02c")
    ax.plot(metrics_df["threshold"], metrics_df["recall"], label="Recall", color="#ff7f00")
    ax.set_title("Validation Precision/Recall vs Threshold")
    ax.set_xlabel("Threshold")
    ax.set_ylabel("Score")
    ax.axvline(best_threshold, color="#e31a1c", linestyle="--")
    ax.legend()
    _save(fig, "val_precision_recall_curve")

    # Confusion matrix at best threshold on test
    pred = test_scores["score"].to_numpy() >= best_threshold
    labels = test_scores["label"].to_numpy()
    tp = int(((labels == 1) & pred).sum())
    tn = int(((labels == 0) & ~pred).sum())
    fp = int(((labels == 0) & pred).sum())
    fn = int(((labels == 1) & ~pred).sum())

    fig, ax = plt.subplots()
    cm = np.array([[tn, fp], [fn, tp]])
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], ["Pred 0", "Pred 1"])
    ax.set_yticks([0, 1], ["True 0", "True 1"])
    ax.set_title("Test Confusion Matrix (Best Threshold)")
    for (i, j), val in np.ndenumerate(cm):
        ax.text(j, i, str(val), ha="center", va="center")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    _save(fig, "test_confusion_matrix")

    summary_md = [
        "# Threshold Tuning",
        "",
        f"Mode: {suffix}",
        f"Best threshold (val F1): {best_threshold}",
        "",
        "## Outputs",
        f"- Tables: {tab_dir}",
        f"- Figures: {fig_dir}",
    ]
    (run_dir / "README.md").write_text("\n".join(summary_md), encoding="utf-8")

    print(str(run_dir))


if __name__ == "__main__":
    main()
