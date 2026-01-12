from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import pandas as pd

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


def _ablation_weights(base: Dict[str, int], drop_keys: List[str]) -> Dict[str, int]:
    weights = dict(base)
    for key in drop_keys:
        if key in weights:
            weights[key] = 0
    return weights


def _score_dataset(
    df: pd.DataFrame,
    *,
    threshold: int,
    rule_weights: Dict[str, int] | None,
    enable_dns_checks: bool,
) -> pd.Series:
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
    return pd.Series(preds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deterministic ablations on test split")
    parser.add_argument(
        "--test",
        default="reports/combined_eval_split_test.csv",
        help="Path to test split CSV",
    )
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--tuned", action="store_true", help="Use tuned rule weights")
    parser.add_argument("--enable-dns", action="store_true", help="Enable DNS checks")
    args = parser.parse_args()

    df = pd.read_csv(args.test)
    if "label" not in df.columns:
        raise ValueError("Test split must include a label column")
    labels = df["label"].astype(int)

    base_weights = TUNED_RULE_WEIGHTS if args.tuned else None
    default_weights = base_weights or {}
    if not default_weights:
        # Empty dict means use defaults in score_email.
        default_weights = {}

    ablations = [
        ("baseline", default_weights),
        ("no_url_heuristics", _ablation_weights(default_weights, ["ip_literal_link", "shortened_url", "url_present"])),
        ("no_urgency", _ablation_weights(default_weights, ["urgency"])),
        ("no_creds_request", _ablation_weights(default_weights, ["creds_request"])),
        ("no_auth_checks", _ablation_weights(default_weights, ["missing_mx", "no_spf", "no_dmarc"])),
        ("no_brand_checks", _ablation_weights(default_weights, ["freemail_brand_claim", "lookalike_domain"])),
    ]

    rows: List[Metrics] = []
    for name, weights in ablations:
        rule_weights = weights if weights else None
        preds = _score_dataset(
            df,
            threshold=args.threshold,
            rule_weights=rule_weights,
            enable_dns_checks=args.enable_dns,
        )
        rows.append(_metrics_from_preds(labels, preds, name))

    out_dir = Path("reports") / f"ablations_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    tab_dir = out_dir / "tables"
    tab_dir.mkdir(parents=True, exist_ok=True)
    out_df = pd.DataFrame([r.__dict__ for r in rows])
    out_df.to_csv(tab_dir / "ablation_metrics.csv", index=False)

    print(str(out_dir))


if __name__ == "__main__":
    main()
