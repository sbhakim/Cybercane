import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact
from app.ai_service import service as ai_service


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


def _metrics_from_preds(df: pd.DataFrame, threshold: int) -> dict[str, float]:
    pred = (df["score"] >= threshold).astype(int)
    tp = int(((df["label"] == 1) & (pred == 1)).sum())
    tn = int(((df["label"] == 0) & (pred == 0)).sum())
    fp = int(((df["label"] == 0) & (pred == 1)).sum())
    fn = int(((df["label"] == 1) & (pred == 0)).sum())
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    return {
        "threshold": float(threshold),
        "tp": float(tp),
        "tn": float(tn),
        "fp": float(fp),
        "fn": float(fn),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate deterministic + AI on test split")
    parser.add_argument("--tuned", action="store_true", help="Use tuned rule weights")
    parser.add_argument(
        "--llm-sample-size",
        type=int,
        default=6,
        help="Number of examples to sample for LLM reason tagging",
    )
    args = parser.parse_args()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = "tuned" if args.tuned else "baseline"
    run_dir = Path("reports") / f"eval_test_{suffix}_{ts}"
    fig_dir = run_dir / "figures"
    tab_dir = run_dir / "tables"
    fig_dir.mkdir(parents=True, exist_ok=True)
    tab_dir.mkdir(parents=True, exist_ok=True)

    test_path = Path("reports/combined_eval_split_test.csv")
    df = pd.read_csv(test_path)

    results = []
    reason_counts = Counter()
    pii_counts = Counter()

    rule_weights = TUNED_RULE_WEIGHTS if args.tuned else None

    for row in df.itertuples(index=False):
        sender = getattr(row, "sender_email", None) or getattr(row, "sender", "") or ""
        subject = getattr(row, "subject", "") or ""
        body = getattr(row, "body", "") or ""
        url_flag = int(getattr(row, "urls", 0) or 0)
        label = int(getattr(row, "label", 0) or 0)

        redacted_body, counts = redact(str(body))
        decision = score_email(
            sender=str(sender),
            subject=str(subject),
            body=redacted_body,
            url_flag=url_flag,
            enable_dns_checks=False,
            rule_weights=rule_weights,
        )

        for r in decision.reasons:
            reason_counts[r] += 1
        for k, v in counts.items():
            pii_counts[k] += int(v)

        results.append(
            {
                "score": decision.score,
                "verdict": decision.verdict,
                "label": label,
            }
        )

    res_df = pd.DataFrame(results)
    verdict_counts = res_df["verdict"].value_counts().to_dict()
    score_hist = res_df["score"].value_counts().sort_index().to_dict()

    metrics_rows = [
        _metrics_from_preds(res_df, threshold=2),
        _metrics_from_preds(res_df, threshold=5),
    ]

    # AI evaluation on test split
    ai_rows = []
    reason_tag_counts = Counter()
    example_rows = []
    ai_enabled = True
    ai_error = ""

    try:
        ai_service._embed_text("connectivity_check")
    except Exception as exc:
        ai_enabled = False
        ai_error = str(exc)

    if ai_enabled:
        for row in df.itertuples(index=False):
            sender = getattr(row, "sender_email", None) or getattr(row, "sender", "") or ""
            subject = getattr(row, "subject", "") or ""
            body = getattr(row, "body", "") or ""
            url_flag = int(getattr(row, "urls", 0) or 0)
            label = int(getattr(row, "label", 0) or 0)

            redacted_body, _ = redact(str(body))
            phase1 = score_email(
                sender=str(sender),
                subject=str(subject),
                body=redacted_body,
                url_flag=url_flag,
                enable_dns_checks=False,
                rule_weights=rule_weights,
            )

            vec = ai_service._embed_text(f"{subject}\n\n{body}".strip()[:8000])
            neighbors = ai_service._nearest_neighbors(vec, limit=8)
            phish_neighbors = [n for n in neighbors if n.label == 1]

            ai_verdict = ai_service._decide_ai_verdict(phase1, phish_neighbors)
            ai_score = ai_service._compute_ai_score(phase1, neighbors)
            top_sim = max((n.similarity for n in neighbors), default=0.0)

            ai_rows.append(
                {
                    "label": label,
                    "phase1_verdict": phase1.verdict,
                    "ai_verdict": ai_verdict,
                    "ai_score": ai_score,
                    "top_similarity": float(top_sim),
                }
            )

        # Small LLM reason sample
        sample_df = df.sample(n=min(args.llm_sample_size, len(df)), random_state=7)
        for row in sample_df.itertuples(index=False):
            sender = getattr(row, "sender_email", None) or getattr(row, "sender", "") or ""
            subject = getattr(row, "subject", "") or ""
            body = getattr(row, "body", "") or ""
            url_flag = int(getattr(row, "urls", 0) or 0)

            redacted_body, _ = redact(str(body))
            phase1 = score_email(
                sender=str(sender),
                subject=str(subject),
                body=redacted_body,
                url_flag=url_flag,
                enable_dns_checks=False,
                rule_weights=rule_weights,
            )
            vec = ai_service._embed_text(f"{subject}\n\n{body}".strip()[:8000])
            neighbors = ai_service._nearest_neighbors(vec, limit=8)
            top_similarity = max((n.similarity for n in neighbors), default=0.0)
            indicators = phase1.indicators or {}
            link_hosts = indicators.get("link_hosts") if isinstance(indicators, dict) else None
            if not isinstance(link_hosts, list):
                link_hosts = []

            reasons = ai_service._summarize_reasons_with_llm(
                subject=str(subject)[:200],
                body=redacted_body[:800],
                phase1=phase1,
                neighbors=neighbors,
            )

            for r in reasons:
                if r.startswith("[") and "]" in r:
                    tag = r.split("]", 1)[0].strip("[]")
                    reason_tag_counts[tag] += 1

            example_rows.append(
                {
                    "subject": str(subject)[:120],
                    "label": int(getattr(row, "label", 0) or 0),
                    "phase1_verdict": phase1.verdict,
                    "phase1_reasons": " | ".join(phase1.reasons),
                    "ai_reasons": " | ".join(reasons[:5]),
                    "top_similarity": float(top_similarity),
                    "link_count": int(len(link_hosts)),
                    "has_mx": indicators.get("has_mx") if isinstance(indicators, dict) else None,
                    "spf_present": indicators.get("spf_present") if isinstance(indicators, dict) else None,
                    "dmarc_present": indicators.get("dmarc_present") if isinstance(indicators, dict) else None,
                    "urgency": bool(indicators.get("urgency", False)) if isinstance(indicators, dict) else False,
                    "creds_request": bool(indicators.get("creds_request", False)) if isinstance(indicators, dict) else False,
                }
            )

    # Tables
    pd.DataFrame(metrics_rows).to_csv(tab_dir / "deterministic_metrics.csv", index=False)
    pd.DataFrame(list(verdict_counts.items()), columns=["verdict", "count"]).to_csv(
        tab_dir / "verdict_distribution.csv", index=False
    )
    pd.DataFrame(list(score_hist.items()), columns=["score", "count"]).to_csv(
        tab_dir / "score_histogram.csv", index=False
    )
    pd.DataFrame(list(reason_counts.items()), columns=["reason", "count"]).sort_values(
        "count", ascending=False
    ).to_csv(tab_dir / "reason_counts.csv", index=False)
    pd.DataFrame(list(pii_counts.items()), columns=["pii_type", "count"]).sort_values(
        "count", ascending=False
    ).to_csv(tab_dir / "pii_redaction_counts.csv", index=False)

    if ai_enabled:
        ai_df = pd.DataFrame(ai_rows)
        ai_df["ai_verdict"].value_counts().reset_index().rename(
            columns={"index": "ai_verdict", "ai_verdict": "count"}
        ).to_csv(tab_dir / "ai_verdict_distribution.csv", index=False)
        ai_df.describe().to_csv(tab_dir / "ai_numeric_summary.csv")
        pd.DataFrame(example_rows).to_csv(tab_dir / "ai_reason_examples.csv", index=False)
        pd.DataFrame(list(reason_tag_counts.items()), columns=["reason_tag", "count"]).sort_values(
            "count", ascending=False
        ).to_csv(tab_dir / "ai_reason_tag_counts.csv", index=False)
    else:
        (tab_dir / "ai_error.txt").write_text(ai_error or "ai disabled", encoding="utf-8")

    # Figures
    plt.rcParams.update({"figure.dpi": 300, "font.size": 10})

    def _save(fig, name: str) -> None:
        fig.savefig(fig_dir / f"{name}.png", dpi=300, bbox_inches="tight")
        fig.savefig(fig_dir / f"{name}.pdf", bbox_inches="tight")
        plt.close(fig)

    fig, ax = plt.subplots()
    ax.bar(verdict_counts.keys(), verdict_counts.values(), color="#2c7fb8")
    ax.set_title("Deterministic Verdict Distribution (Test)")
    ax.set_ylabel("Count")
    _save(fig, "deterministic_verdict_distribution")

    fig, ax = plt.subplots()
    ax.bar([str(k) for k in score_hist.keys()], score_hist.values(), color="#f03b20")
    ax.set_title("Deterministic Score Histogram (Test)")
    ax.set_xlabel("Score")
    ax.set_ylabel("Count")
    _save(fig, "deterministic_score_histogram")

    reason_top = reason_counts.most_common(10)
    if reason_top:
        fig, ax = plt.subplots(figsize=(6, 4))
        labels, counts = zip(*reason_top)
        ax.barh(labels[::-1], counts[::-1], color="#31a354")
        ax.set_title("Top Deterministic Reasons (Test)")
        ax.set_xlabel("Count")
        _save(fig, "deterministic_top_reasons")

    if pii_counts:
        fig, ax = plt.subplots()
        labels, counts = zip(*pii_counts.items())
        ax.bar(labels, counts, color="#756bb1")
        ax.set_title("PII Redaction Counts (Test)")
        ax.set_ylabel("Count")
        _save(fig, "pii_redaction_counts")

    # Metrics bar chart (threshold=2)
    m2 = metrics_rows[0]
    fig, ax = plt.subplots()
    ax.bar(["precision", "recall", "f1"], [m2["precision"], m2["recall"], m2["f1"]], color="#636363")
    ax.set_ylim(0, 1)
    ax.set_title("Deterministic Metrics (Test, threshold=2)")
    _save(fig, "deterministic_metrics_threshold_2")

    if ai_enabled:
        ai_df = pd.DataFrame(ai_rows)
        ai_verdict_counts = ai_df["ai_verdict"].value_counts().to_dict()
        fig, ax = plt.subplots()
        ax.bar(ai_verdict_counts.keys(), ai_verdict_counts.values(), color="#636363")
        ax.set_title("AI Verdict Distribution (Test)")
        ax.set_ylabel("Count")
        _save(fig, "ai_verdict_distribution")

        fig, ax = plt.subplots()
        ax.hist(ai_df["top_similarity"], bins=20, color="#9ecae1", edgecolor="black")
        ax.set_title("Top Neighbor Similarity (Test)")
        ax.set_xlabel("Cosine Similarity")
        ax.set_ylabel("Count")
        _save(fig, "ai_similarity_histogram")

        if reason_tag_counts:
            fig, ax = plt.subplots()
            tags, counts = zip(*reason_tag_counts.items())
            ax.bar(tags, counts, color="#ff7f00")
            ax.set_title("LLM Reason Tag Counts (Test)")
            ax.set_ylabel("Count")
            _save(fig, "ai_reason_tag_counts")

    summary_md = [
        "# Test Split Evaluation",
        "",
        f"Dataset: {test_path.name}",
        f"Rows: {len(df)}",
        "",
        "## Notes",
        "- Test split only (train used for embeddings).",
        "- DNS checks disabled for deterministic scoring.",
        f"- Mode: {suffix}",
        f"- AI enabled: {ai_enabled}",
        f"- LLM sample size: {args.llm_sample_size}",
        "",
        "## Outputs",
        f"- Tables: {tab_dir}",
        f"- Figures: {fig_dir}",
    ]
    (run_dir / "README.md").write_text("\n".join(summary_md), encoding="utf-8")

    print(str(run_dir))


if __name__ == "__main__":
    main()
