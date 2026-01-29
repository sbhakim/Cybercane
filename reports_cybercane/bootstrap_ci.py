from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd

from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact


TUNED_RULE_WEIGHTS = {
    "freemail_brand_claim": 2,
    "lookalike_domain": 2,
    "ip_literal_link": 2,
    "shortened_url": 2,
    "urgency": 2,
    "creds_request": 2,
    "missing_mx": 2,
    "no_spf": 2,
    "no_dmarc": 1,
    "strict_dmarc_missing_align": 3,
    # REMOVED: "url_present": 1  (ablation showed non-discriminative)
}


@dataclass
class MetricCI:
    metric: str
    mean: float
    lower: float
    upper: float


def _metrics(labels: np.ndarray, preds: np.ndarray) -> Dict[str, float]:
    tp = int(((labels == 1) & (preds == 1)).sum())
    tn = int(((labels == 0) & (preds == 0)).sum())
    fp = int(((labels == 0) & (preds == 1)).sum())
    fn = int(((labels == 1) & (preds == 0)).sum())
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _score_dataset(
    df: pd.DataFrame,
    *,
    threshold: int,
    rule_weights: Dict[str, int] | None,
    enable_dns_checks: bool,
) -> np.ndarray:
    preds: List[int] = []
    for row in df.itertuples(index=False):
        sender = getattr(row, "sender_email", None) or getattr(row, "sender", "") or ""
        subject = getattr(row, "subject", "") or ""
        body = getattr(row, "body", "") or ""
        url_flag = int(getattr(row, "urls", 0) or 0)

        redacted_body, _ = redact(str(body))
        decision = score_email(
            sender=str(sender),
            subject=str(subject),
            body=redacted_body,
            url_flag=url_flag,
            enable_dns_checks=enable_dns_checks,
            rule_weights=rule_weights,
        )
        preds.append(1 if decision.score >= threshold else 0)
    return np.array(preds, dtype=int)


def _bootstrap_ci(
    labels: np.ndarray, preds: np.ndarray, *, n_boot: int, seed: int
) -> Dict[str, MetricCI]:
    rng = np.random.default_rng(seed)
    n = labels.shape[0]
    acc = np.zeros(n_boot, dtype=float)
    prec = np.zeros(n_boot, dtype=float)
    rec = np.zeros(n_boot, dtype=float)
    f1 = np.zeros(n_boot, dtype=float)

    for i in range(n_boot):
        idx = rng.integers(0, n, size=n)
        m = _metrics(labels[idx], preds[idx])
        acc[i] = m["accuracy"]
        prec[i] = m["precision"]
        rec[i] = m["recall"]
        f1[i] = m["f1"]

    def ci(values: np.ndarray, name: str) -> MetricCI:
        return MetricCI(
            metric=name,
            mean=float(values.mean()),
            lower=float(np.percentile(values, 2.5)),
            upper=float(np.percentile(values, 97.5)),
        )

    return {
        "accuracy": ci(acc, "Accuracy"),
        "precision": ci(prec, "Precision"),
        "recall": ci(rec, "Recall"),
        "f1": ci(f1, "F1"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap confidence intervals for deterministic metrics")
    parser.add_argument(
        "--test",
        default="reports/combined_eval_split_test.csv",
        help="Path to test split CSV",
    )
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--tuned", action="store_true", help="Use tuned rule weights")
    parser.add_argument("--enable-dns", action="store_true", help="Enable DNS checks")
    parser.add_argument("--n-boot", type=int, default=1000, help="Number of bootstrap samples")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = pd.read_csv(args.test)
    if "label" not in df.columns:
        raise ValueError("Test split must include a label column")
    labels = df["label"].astype(int).to_numpy()

    rule_weights = TUNED_RULE_WEIGHTS if args.tuned else None
    preds = _score_dataset(
        df,
        threshold=args.threshold,
        rule_weights=rule_weights,
        enable_dns_checks=args.enable_dns,
    )

    ci = _bootstrap_ci(labels, preds, n_boot=args.n_boot, seed=args.seed)
    rows = [ci[key].__dict__ for key in ["accuracy", "precision", "recall", "f1"]]

    out_dir = Path("reports") / f"bootstrap_ci_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    tab_dir = out_dir / "tables"
    tab_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(tab_dir / "deterministic_ci.csv", index=False)
    print(str(out_dir))


if __name__ == "__main__":
    main()
