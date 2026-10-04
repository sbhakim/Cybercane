"""
CyberCane risk score and calibrated decision rule.

Single definition shared by the API and documented in the paper:

  n(x)    = 0.65 * s_1 + 0.35 * mean(s_1, s_2, s_3)
            s_i = i-th largest cosine similarity of x to the phishing index
  p(x)    = 1.0 if Phase 1 = phishing, 0.6 if needs_review, 0.0 if benign
  risk(x) = clip(max(n, 0.7 * n + 0.3 * p), 0, 1)

The risk is a monotone ranking score, not a probability. Verdicts come from
thresholds calibrated on source-validation negatives for a target FPR budget
(see scripts/calibrate_risk_thresholds.py); the 0-10 display score is
round(10 * risk).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

W_TOP, W_AVG3 = 0.65, 0.35
W_NEIGHBOR, W_PHASE1 = 0.7, 0.3
PHASE1_SIGNAL = {"phishing": 1.0, "needs_review": 0.6, "benign": 0.0}


def neighbor_signal(similarities: Iterable[float]) -> float:
    sims = sorted((float(s) for s in similarities), reverse=True)
    if not sims:
        return 0.0
    top3 = sims[:3]
    return W_TOP * sims[0] + W_AVG3 * (sum(top3) / len(top3))


def combine(n: float, phase1_verdict: str) -> float:
    """Fuse a neighbor signal with the Phase 1 verdict into the [0, 1] risk."""
    p = PHASE1_SIGNAL.get(phase1_verdict, 0.0)
    return max(0.0, min(1.0, max(n, W_NEIGHBOR * n + W_PHASE1 * p)))


def risk_score(similarities: Iterable[float], phase1_verdict: str) -> float:
    return combine(neighbor_signal(similarities), phase1_verdict)


@dataclass(frozen=True)
class RiskThresholds:
    phishing: float          # risk above this -> "phishing" (calibrated to the FPR budget)
    review: float            # risk above this -> "needs_review" (calibrated to a wider budget)
    fpr_budget: float
    review_budget: float
    source: str


def load_risk_thresholds() -> Optional[RiskThresholds]:
    """Read calibrated thresholds from RISK_THRESHOLDS_PATH; None if unset or unreadable."""
    path = os.getenv("RISK_THRESHOLDS_PATH", "").strip()
    if not path or not Path(path).exists():
        return None
    try:
        d = json.loads(Path(path).read_text())
        return RiskThresholds(float(d["risk_threshold_phishing"]), float(d["risk_threshold_review"]),
                              float(d["fpr_budget"]), float(d["review_budget"]), path)
    except Exception:
        return None


def decide(risk: float, phase1_verdict: str, thr: RiskThresholds) -> str:
    """
    Calibrated three-way verdict. A Phase 1 "phishing" verdict (hard symbolic
    violations, e.g. failed DNS/authentication) passes through unchanged; this
    path is part of the deployed rule but could not be evaluated on the public,
    header-less corpora.
    """
    if phase1_verdict == "phishing" or risk > thr.phishing:
        return "phishing"
    if risk > thr.review:
        return "needs_review"
    return "benign"
