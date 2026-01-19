"""
Multi-threshold operating point evaluation for CyberCane.

This script evaluates multiple Phase 1 and RAG threshold configurations on a
held-out test set. It reuses deterministic scoring and RAG retrieval but skips
LLM explanations to keep costs predictable.

Notes:
- Phase 1 scores are integers, so fractional thresholds effectively round up.
- Similarity stats are computed once per email and reused across configs.
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import pandas as pd

from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact
from app.ai_service import service as ai_service


@dataclass
class OperatingPoint:
    name: str
    phase1_low: float
    phase1_high: float
    rag_sim_high: float
    rag_sim_low: float
    rag_avg_top3_high: float
    rag_avg_top3_low: float
    use_case: str


@dataclass
class Sample:
    label: int
    score: int
    sims: List[float]


def _clean_sender(sender_val: object) -> str:
    """Extract a valid-ish email address from messy sender strings."""
    s = str(sender_val or "").strip()
    if "<" in s and ">" in s:
        try:
            candidate = s.split("<", 1)[1].split(">", 1)[0].strip()
            if "@" in candidate:
                return candidate.replace(" ", "")
        except Exception:
            pass

    if "@" in s:
        return s.replace(" ", "")

    return "unknown@example.com"


def _coerce_int(value: object, default: int = 0) -> int:
    if value is None:
        return default
    s = str(value).strip()
    if s == "":
        return default
    try:
        return int(float(s))
    except Exception:
        return default


def _get_url_flag(row: pd.Series) -> int:
    if "url" in row:
        return _coerce_int(row.get("url"), 0)
    if "urls" in row:
        return _coerce_int(row.get("urls"), 0)
    return 0


def _combine_subject_body(subject: str, body: str, cap: int = 8000) -> str:
    return f"{subject}\n\n{body}".strip()[:cap]


def _custom_phase1_verdict(score: int, low: float, high: float) -> str:
    if score >= high:
        return "phishing"
    if score >= low:
        return "needs_review"
    return "benign"


def _avg_top3(sims: List[float]) -> float:
    if not sims:
        return 0.0
    top3 = sims[:3]
    return sum(top3) / len(top3)


def _apply_limit(
    df: pd.DataFrame,
    *,
    limit: Optional[int],
    sample: bool,
    stratified: bool,
    seed: int,
) -> pd.DataFrame:
    if not limit or limit <= 0:
        return df

    if sample:
        if stratified and "label" in df.columns:
            pos = df[df["label"] == 1]
            neg = df[df["label"] == 0]
            half = max(1, limit // 2)
            pos_n = min(len(pos), half)
            neg_n = min(len(neg), limit - pos_n)
            frames = []
            if pos_n > 0:
                frames.append(pos.sample(n=pos_n, random_state=seed))
            if neg_n > 0:
                frames.append(neg.sample(n=neg_n, random_state=seed))
            if frames:
                df_sample = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=seed)
                return df_sample.reset_index(drop=True)
        return df.sample(n=min(limit, len(df)), random_state=seed).reset_index(drop=True)

    return df.head(limit).reset_index(drop=True)


def _load_samples(
    df: pd.DataFrame,
    *,
    k_neighbors: int,
    enable_dns_checks: bool,
    redact_for_embedding: bool,
    total_rows: int,
    progress_every: int,
) -> List[Sample]:
    samples: List[Sample] = []
    skipped = 0
    start_time = time.time()

    row_iter = df.itertuples(index=False)

    for idx, row in enumerate(row_iter, 1):
        label_raw = getattr(row, "label", None)
        if label_raw is None or str(label_raw).strip() == "":
            skipped += 1
            continue
        try:
            label = int(float(label_raw))
        except Exception:
            skipped += 1
            continue
        if label not in (0, 1):
            skipped += 1
            continue

        sender = getattr(row, "sender_email", None) or getattr(row, "sender", "") or ""
        subject = getattr(row, "subject", "") or ""
        body = getattr(row, "body", "") or ""
        url_flag = _coerce_int(getattr(row, "urls", None), None)
        if url_flag is None:
            url_flag = _coerce_int(getattr(row, "url", None), 0)

        sender = _clean_sender(sender)
        subject = str(subject)
        body = str(body)

        redacted_body, _ = redact(body)
        decision = score_email(
            sender=sender,
            subject=subject,
            body=redacted_body,
            url_flag=int(url_flag),
            enable_dns_checks=enable_dns_checks,
        )

        embed_body = redacted_body if redact_for_embedding else body
        doc_text = _combine_subject_body(subject, embed_body)
        vec = ai_service._embed_text(doc_text)
        neighbors = ai_service._nearest_neighbors(vec, limit=k_neighbors)
        sims = sorted([float(n.similarity) for n in neighbors], reverse=True)

        samples.append(Sample(label=label, score=int(decision.score), sims=sims))

        if progress_every > 0 and idx % progress_every == 0:
            elapsed = max(0.001, time.time() - start_time)
            rate = idx / elapsed
            remaining = max(0, total_rows - idx)
            eta = remaining / rate if rate > 0 else 0.0
            print(
                f"Processed {idx}/{total_rows} rows "
                f"({rate:.2f} rows/sec, eta {eta/60:.1f} min)",
                flush=True,
            )

    if skipped:
        print(f"Skipped {skipped} rows with missing/invalid labels")

    return samples


def _evaluate_config(samples: Iterable[Sample], config: OperatingPoint) -> Dict[str, float]:
    tp = tn = fp = fn = 0
    for sample in samples:
        phase1_verdict = _custom_phase1_verdict(sample.score, config.phase1_low, config.phase1_high)

        if phase1_verdict == "phishing":
            pred_label = 1
        else:
            top_sim = sample.sims[0] if sample.sims else 0.0
            avg_top3 = _avg_top3(sample.sims)

            if top_sim >= config.rag_sim_high or (
                phase1_verdict == "needs_review" and avg_top3 >= config.rag_avg_top3_high
            ):
                pred_label = 1
            elif top_sim >= config.rag_sim_low or avg_top3 >= config.rag_avg_top3_low:
                pred_label = 0
            else:
                pred_label = 0

        if sample.label == 1 and pred_label == 1:
            tp += 1
        elif sample.label == 0 and pred_label == 1:
            fp += 1
        elif sample.label == 0 and pred_label == 0:
            tn += 1
        elif sample.label == 1 and pred_label == 0:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "accuracy": accuracy,
    }


def _default_operating_points() -> List[OperatingPoint]:
    return [
        OperatingPoint(
            name="Baseline (Pipeline)",
            phase1_low=2,
            phase1_high=5,
            rag_sim_high=0.70,
            rag_sim_low=0.55,
            rag_avg_top3_high=0.68,
            rag_avg_top3_low=0.52,
            use_case="Current production thresholds",
        ),
        OperatingPoint(
            name="Conservative",
            phase1_low=1,
            phase1_high=4,
            rag_sim_high=0.65,
            rag_sim_low=0.50,
            rag_avg_top3_high=0.60,
            rag_avg_top3_low=0.45,
            use_case="High-stakes clinical workflows",
        ),
        OperatingPoint(
            name="Balanced",
            phase1_low=1,
            phase1_high=3,
            rag_sim_high=0.60,
            rag_sim_low=0.45,
            rag_avg_top3_high=0.55,
            rag_avg_top3_low=0.40,
            use_case="General healthcare organizations",
        ),
        OperatingPoint(
            name="Moderate",
            phase1_low=0,
            phase1_high=3,
            rag_sim_high=0.55,
            rag_sim_low=0.40,
            rag_avg_top3_high=0.50,
            rag_avg_top3_low=0.35,
            use_case="High-volume screening",
        ),
        OperatingPoint(
            name="Aggressive",
            phase1_low=0,
            phase1_high=2,
            rag_sim_high=0.50,
            rag_sim_low=0.35,
            rag_avg_top3_high=0.45,
            rag_avg_top3_low=0.30,
            use_case="Maximum coverage, staffing for review",
        ),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate multiple operating points for CyberCane")
    parser.add_argument("--test", default="reports/combined_eval_split_test.csv")
    parser.add_argument("--output", default="reports/operating_points_evaluation.csv")
    parser.add_argument("--k", type=int, default=8)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--sample", action="store_true", help="Sample rows instead of taking head()")
    parser.add_argument(
        "--stratified",
        action="store_true",
        help="When sampling, balance by label if possible",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--progress-every", type=int, default=100)
    parser.add_argument("--enable-dns", action="store_true")
    parser.add_argument(
        "--redact-embed",
        action="store_true",
        help="Use redacted body text for embeddings (privacy-first, may reduce recall)",
    )
    parser.add_argument("--single", action="store_true", help="Evaluate a single custom config")
    parser.add_argument("--phase1-low", type=float, default=2.0)
    parser.add_argument("--phase1-high", type=float, default=5.0)
    parser.add_argument("--rag-sim-high", type=float, default=0.88)
    parser.add_argument("--rag-sim-low", type=float, default=0.75)
    parser.add_argument("--rag-avg-top3-high", type=float, default=0.82)
    parser.add_argument("--rag-avg-top3-low", type=float, default=0.72)
    args = parser.parse_args()

    df = pd.read_csv(args.test)
    if "label" not in df.columns:
        raise ValueError("Test split must include a label column")

    df_eval = _apply_limit(
        df,
        limit=args.limit,
        sample=args.sample,
        stratified=args.stratified,
        seed=args.seed,
    )

    configs = _default_operating_points()
    if args.single:
        configs = [
            OperatingPoint(
                name="Custom",
                phase1_low=args.phase1_low,
                phase1_high=args.phase1_high,
                rag_sim_high=args.rag_sim_high,
                rag_sim_low=args.rag_sim_low,
                rag_avg_top3_high=args.rag_avg_top3_high,
                rag_avg_top3_low=args.rag_avg_top3_low,
                use_case="custom",
            )
        ]

    print(f"Loading embeddings and neighbors for {len(df_eval)} rows (total={len(df)})...")
    samples = _load_samples(
        df_eval,
        k_neighbors=args.k,
        enable_dns_checks=args.enable_dns,
        redact_for_embedding=args.redact_embed,
        total_rows=len(df_eval),
        progress_every=args.progress_every,
    )

    rows: List[Dict[str, object]] = []
    for config in configs:
        metrics = _evaluate_config(samples, config)
        row = {
            "operating_mode": config.name,
            "use_case": config.use_case,
            "phase1_low": config.phase1_low,
            "phase1_high": config.phase1_high,
            "rag_sim_high": config.rag_sim_high,
            "rag_sim_low": config.rag_sim_low,
            "rag_avg_top3_high": config.rag_avg_top3_high,
            "rag_avg_top3_low": config.rag_avg_top3_low,
            **metrics,
        }
        rows.append(row)
        print(
            f"{config.name}: precision={metrics['precision']:.1%} "
            f"recall={metrics['recall']:.1%} f1={metrics['f1']:.3f} "
            f"fpr={metrics['fpr']:.2%}"
        )

    out_df = pd.DataFrame(rows)
    out_df.to_csv(args.output, index=False)
    print(f"Wrote results to {args.output}")


if __name__ == "__main__":
    main()
