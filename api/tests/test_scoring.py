import types

import numpy as np
import pytest

from app.ai_service import scoring, service
from app.schemas import EmailIn, NeighborOut, RedactionsOut, ScanOut


def _phase1(verdict: str) -> ScanOut:
    return ScanOut(verdict=verdict, score=0, reasons=[], indicators={},
                   redactions=RedactionsOut(types={}, count=0), redacted_body="")


def _legacy_score(verdict, sims):
    """Pre-refactor _compute_ai_score, kept verbatim as the reference."""
    top = sims[0]
    avg3 = sum(sims[:3]) / min(3, len(sims))
    n = 0.65 * top + 0.35 * avg3
    p = 1.0 if verdict == "phishing" else (0.6 if verdict == "needs_review" else 0.0)
    return int(round(max(0.0, min(1.0, max(n, 0.7 * n + 0.3 * p))) * 10))


def test_refactored_score_equals_legacy_formula():
    rng = np.random.default_rng(0)
    for _ in range(2000):
        sims = sorted(rng.uniform(-0.2, 1.0, rng.integers(1, 9)).tolist(), reverse=True)
        verdict = str(rng.choice(["benign", "needs_review", "phishing"]))
        nb = [NeighborOut(id=i, label=1, similarity=s) for i, s in enumerate(sims)]
        assert service._compute_ai_score(_phase1(verdict), nb) == _legacy_score(verdict, sims)


def test_risk_matches_experiment_scorer():
    """The experiments compute n = 0.65*top + 0.35*mean(top3) on sorted similarities."""
    sims = [0.9, 0.7, 0.4, 0.1]
    n = 0.65 * 0.9 + 0.35 * (0.9 + 0.7 + 0.4) / 3
    assert scoring.risk_score(sims, "benign") == pytest.approx(n)
    assert scoring.risk_score(sims, "needs_review") == pytest.approx(max(n, 0.7 * n + 0.3 * 0.6))


@pytest.mark.parametrize("risk, p1, expected", [
    (0.90, "benign", "phishing"),
    (0.50, "benign", "needs_review"),
    (0.10, "benign", "benign"),
    (0.10, "phishing", "phishing"),   # hard symbolic violation passes through
])
def test_calibrated_decision(risk, p1, expected):
    thr = scoring.RiskThresholds(phishing=0.8, review=0.4, fpr_budget=0.01, review_budget=0.08, source="t")
    assert scoring.decide(risk, p1, thr) == expected


def _stub_client():
    emb = types.SimpleNamespace(create=lambda model, input: types.SimpleNamespace(
        data=[types.SimpleNamespace(embedding=[0.0] * 1536)]))
    chat = types.SimpleNamespace(create=lambda **kw: types.SimpleNamespace(
        choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="[AUTH] test"))]))
    return types.SimpleNamespace(embeddings=emb, chat=types.SimpleNamespace(completions=chat))


def test_retrieval_failure_is_flagged_degraded(monkeypatch):
    monkeypatch.setattr(service, "_build_ai_client", lambda prefer_deepseek=False: (_stub_client(), "openai"))

    def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(service, "_nearest_neighbors", boom)
    out = service.analyze_email(EmailIn(sender="a@b.c", subject="s", body="b"), _phase1("benign"))
    assert out.degraded is True and out.neighbors == []


def test_calibrated_rule_is_used_when_configured(monkeypatch):
    monkeypatch.setattr(service, "_build_ai_client", lambda prefer_deepseek=False: (_stub_client(), "openai"))
    monkeypatch.setattr(service, "_nearest_neighbors", lambda vec, limit=8, include_benign=False: [
        NeighborOut(id=1, label=1, similarity=0.95)])
    monkeypatch.setattr(service, "RISK_THRESHOLDS", scoring.RiskThresholds(0.8, 0.4, 0.01, 0.08, "t"))
    out = service.analyze_email(EmailIn(sender="a@b.c", subject="s", body="b"), _phase1("benign"))
    assert out.decision_rule == "calibrated" and out.ai_verdict == "phishing"
    assert out.ai_risk == pytest.approx(0.95) and out.degraded is False
