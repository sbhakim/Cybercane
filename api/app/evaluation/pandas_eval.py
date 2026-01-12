from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

from app.pipeline.pii import redact
from app.pipeline.deterministic import score_email


@dataclass
class EvalSummary:
    total_rows: int
    processed_rows: int
    skipped_rows: int
    label_counts: Dict[str, int]
    threshold: int
    score_histogram: Dict[str, int]
    metrics: Dict[str, float]


def load_dataset(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    return df


def compute_dataset_stats(df: pd.DataFrame) -> Dict[str, object]:
    stats: Dict[str, object] = {}
    stats["num_rows"] = int(len(df))
    stats["columns"] = list(df.columns)
    stats["missing_per_column"] = {
        c: int(df[c].isna().sum()) + int((df[c] == "").sum() if df[c].dtype == object else 0)
        for c in df.columns
    }

    # Label distribution
    if "label" in df.columns:
        label_counts = df["label"].value_counts(dropna=False).to_dict()
        stats["label_distribution"] = {str(k): int(v) for k, v in label_counts.items()}
    else:
        stats["label_distribution"] = {}

    # URL flag distribution (support both url/urls)
    url_col = "url" if "url" in df.columns else ("urls" if "urls" in df.columns else None)
    if url_col:
        vc = df[url_col].fillna(0).astype(int).value_counts().to_dict()
        stats["url_flag_distribution"] = {str(k): int(v) for k, v in vc.items()}
    else:
        stats["url_flag_distribution"] = {}

    # Text lengths
    for col in ["subject", "body"]:
        if col in df.columns:
            lengths = df[col].fillna("").astype(str).str.len()
            stats[f"{col}_length"] = {
                "min": float(lengths.min()),
                "p25": float(lengths.quantile(0.25)),
                "mean": float(lengths.mean()),
                "p75": float(lengths.quantile(0.75)),
                "max": float(lengths.max()),
            }
        else:
            stats[f"{col}_length"] = {"min": 0, "p25": 0, "mean": 0, "p75": 0, "max": 0}

    # Sender domain top 20 (best-effort parse angle-bracket emails)
    def extract_email(v: str) -> str:
        s = str(v or "")
        if "<" in s and ">" in s:
            try:
                return s.split("<", 1)[1].split(">", 1)[0]
            except Exception:
                return s
        return s

    def domain_of(v: str) -> str:
        s = str(v or "")
        return s.rsplit("@", 1)[-1].lower().strip() if "@" in s else ""

    if "sender" in df.columns:
        domains = df["sender"].fillna("").map(extract_email).map(domain_of)
        top = domains[domains != ""].value_counts().head(20)
        stats["top_sender_domains"] = [(k, int(v)) for k, v in top.items()]
    else:
        stats["top_sender_domains"] = []

    return stats


def _binary_from_score(score: int, threshold: int) -> int:
    return 1 if int(score) >= int(threshold) else 0


def evaluate_pipeline(
    df: pd.DataFrame,
    limit: Optional[int] = None,
    enable_dns_checks: bool = False,
    threshold: int = 2,
) -> Tuple[pd.DataFrame, EvalSummary]:
    # Normalize columns
    sender_series = df.get("sender_email").fillna("").astype(str)
    if sender_series.eq("").all() and "sender" in df.columns:
        sender_series = df["sender"].fillna("").astype(str)

    subject_series = df.get("subject", pd.Series([""] * len(df))).fillna("").astype(str)
    body_series = df.get("body", pd.Series([""] * len(df))).fillna("").astype(str)
    url_col = "url" if "url" in df.columns else ("urls" if "urls" in df.columns else None)
    url_series = df.get(url_col, pd.Series([0] * len(df))).fillna(0).astype(int) if url_col else pd.Series([0] * len(df))
    label_series = df.get("label")

    n = len(df) if limit is None else min(limit, len(df))
    results = []
    processed = 0
    skipped = 0
    label_counts: Dict[str, int] = {"0": 0, "1": 0, "missing": 0}

    for i in range(n):
        label_val = None
        if label_series is not None:
            try:
                v = label_series.iloc[i]
                if pd.notna(v) and str(v).strip() != "":
                    label_val = int(v)
            except Exception:
                label_val = None

        if label_val is None:
            skipped += 1
            label_counts["missing"] += 1
            continue

        label_counts[str(label_val)] += 1

        sender = sender_series.iloc[i]
        subject = subject_series.iloc[i]
        body = body_series.iloc[i]
        url_flag = int(url_series.iloc[i])

        redacted_body, red_counts = redact(body)
        decision = score_email(
            sender=sender,
            subject=subject,
            body=redacted_body,
            url_flag=url_flag,
            enable_dns_checks=enable_dns_checks,
        )

        results.append(
            {
                "sender": sender,
                "subject": subject,
                "label": label_val,
                "verdict": decision.verdict,
                "score": decision.score,
                "pred_label": _binary_from_score(decision.score, threshold),
                "reasons": decision.reasons,
                "pii_redactions": red_counts,
            }
        )
        processed += 1

    out_df = pd.DataFrame(results)
    if not out_df.empty:
        # Score histogram (as string keys for JSON stability)
        hist = out_df["score"].value_counts().sort_index().to_dict()
        score_hist = {str(k): int(v) for k, v in hist.items()}
        tp = int(((out_df["label"] == 1) & (out_df["pred_label"] == 1)).sum())
        tn = int(((out_df["label"] == 0) & (out_df["pred_label"] == 0)).sum())
        fp = int(((out_df["label"] == 0) & (out_df["pred_label"] == 1)).sum())
        fn = int(((out_df["label"] == 1) & (out_df["pred_label"] == 0)).sum())
        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    else:
        tp = tn = fp = fn = 0
        accuracy = precision = recall = f1 = 0.0
        score_hist = {}

    summary = EvalSummary(
        total_rows=int(len(df)),
        processed_rows=int(processed),
        skipped_rows=int(skipped),
        label_counts=label_counts,
        threshold=int(threshold),
        score_histogram=score_hist,
        metrics={
            "tp": float(tp),
            "tn": float(tn),
            "fp": float(fp),
            "fn": float(fn),
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
        },
    )

    return out_df, summary


def write_outputs(
    *,
    base_datasets_dir: Path,
    dataset_name: str,
    dataset_stats: Dict[str, object],
    eval_df: pd.DataFrame,
    summary: EvalSummary,
) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = base_datasets_dir / "evaluation_results" / f"evaluation_results_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write dataset stats JSON
    (out_dir / f"{dataset_name}_stats.json").write_text(
        json.dumps(dataset_stats, indent=2), encoding="utf-8"
    )

    # Write evaluation details CSV and JSON
    eval_csv_path = out_dir / f"{dataset_name}_evaluation.csv"
    eval_json_path = out_dir / f"{dataset_name}_evaluation.json"
    eval_df.to_csv(eval_csv_path, index=False)
    eval_df.to_json(eval_json_path, orient="records", indent=2, force_ascii=False)

    # Write summary JSON
    (out_dir / f"{dataset_name}_summary.json").write_text(
        json.dumps({**dataset_stats, "summary": asdict(summary)}, indent=2), encoding="utf-8"
    )

    return out_dir


