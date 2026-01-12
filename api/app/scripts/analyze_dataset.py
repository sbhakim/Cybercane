"""
Initial analysis of the Nazario dataset.

This script:
- Loads `datasets/Nazario.csv`
- Prints schema overview, row counts, missingness per column
- Computes label balance (0/1)
- Basic text length stats for `subject` and `body`
- URL flag distribution
- Simple sender domain distribution (top 20)
- Heuristic content cues prevalence (urgency/credential keywords)

Run from repo root:
    py -m app.scripts.analyze_dataset | cat

Note: Uses only stdlib to avoid adding bulky deps.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Dict, Iterable, List, Optional, Tuple


DATASET_FILE = Path(__file__).resolve().parents[3] / "datasets" / "Nazario.csv"


def _read_rows(path: Path, limit: Optional[int] = None) -> List[dict]:
    rows: List[dict] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            rows.append(row)
            if limit is not None and i + 1 >= limit:
                break
    return rows


def _coerce_int(value: str | int | None, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(str(value).strip())
    except Exception:
        return default


def _extract_email(text: str) -> str:
    if not text:
        return ""
    m = re.search(r"<([^>]+)>", text)
    if m:
        return m.group(1).strip()
    return text.strip()


def _domain_of(email: str) -> str:
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].lower().strip()


def _length(s: Optional[str]) -> int:
    return len(s or "")


def analyze(rows: List[dict]) -> Dict[str, object]:
    cols = rows[0].keys() if rows else []
    n_rows = len(rows)

    missing = {c: 0 for c in cols}
    for r in rows:
        for c in cols:
            if r.get(c) in (None, ""):
                missing[c] += 1

    # Label distribution
    labels = Counter()
    for r in rows:
        v = r.get("label")
        if v is None or str(v).strip() == "":
            labels["missing"] += 1
        else:
            try:
                labels[int(str(v).strip())] += 1
            except Exception:
                labels["invalid"] += 1

    # URL flags
    url_flags = Counter()
    for r in rows:
        uf = r.get("url") if "url" in r else r.get("urls")
        url_flags[_coerce_int(uf, 0)] += 1

    # Text length stats
    subj_lengths = [_length(r.get("subject")) for r in rows]
    body_lengths = [_length(r.get("body")) for r in rows]

    def summarize_lengths(values: List[int]) -> Dict[str, float]:
        if not values:
            return {"min": 0, "p25": 0, "mean": 0, "p75": 0, "max": 0}
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        p25 = sorted_vals[int(0.25 * (n - 1))]
        p75 = sorted_vals[int(0.75 * (n - 1))]
        return {
            "min": float(sorted_vals[0]),
            "p25": float(p25),
            "mean": float(mean(sorted_vals)),
            "p75": float(p75),
            "max": float(sorted_vals[-1]),
        }

    # Sender domains
    domain_counts = Counter()
    for r in rows:
        dom = _domain_of(_extract_email(r.get("sender", "")))
        if dom:
            domain_counts[dom] += 1

    # Content cues heuristics
    urgency_kw = {"urgent", "verify your account", "password", "suspend", "update"}
    creds_kw = {"password", "login", "ssn", "credit card", "bank account"}
    urgency_hits = 0
    creds_hits = 0
    for r in rows:
        text = (r.get("subject", "") + "\n" + r.get("body", "")).lower()
        if any(k in text for k in urgency_kw):
            urgency_hits += 1
        if any(k in text for k in creds_kw):
            creds_hits += 1

    return {
        "num_rows": n_rows,
        "columns": list(cols),
        "missing_per_column": missing,
        "label_distribution": dict(labels),
        "url_flag_distribution": dict(url_flags),
        "subject_length": summarize_lengths(subj_lengths),
        "body_length": summarize_lengths(body_lengths),
        "top_sender_domains": domain_counts.most_common(20),
        "heuristics": {"urgency_hits": urgency_hits, "creds_hits": creds_hits},
    }


def main(limit: Optional[int] = None) -> None:
    if not DATASET_FILE.exists():
        print(f"Dataset not found at: {DATASET_FILE}")
        return
    rows = _read_rows(DATASET_FILE, limit=limit)
    stats = analyze(rows)
    print("=== Dataset Overview ===")
    print(f"Rows: {stats['num_rows']}")
    print("Columns:", ", ".join(stats["columns"]))
    print("\n=== Missingness (counts) ===")
    for k, v in stats["missing_per_column"].items():
        print(f"{k}: {v}")
    print("\n=== Label Distribution ===", stats["label_distribution"]) 
    print("=== URL Flag Distribution ===", stats["url_flag_distribution"]) 
    print("\n=== Subject Length ===", stats["subject_length"]) 
    print("=== Body Length ===", stats["body_length"]) 
    print("\n=== Top Sender Domains (top 20) ===")
    for dom, cnt in stats["top_sender_domains"]:
        print(f"{dom}: {cnt}")
    print("\n=== Heuristic Content Cues ===", stats["heuristics"]) 


if __name__ == "__main__":
    main()


