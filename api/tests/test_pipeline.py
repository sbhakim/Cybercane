from app.pipeline.classify import classify_email
import app.pipeline.deterministic as det


def test_classify_email_shapes(monkeypatch):
    # Stub DNS/auth checks to keep tests offline
    monkeypatch.setattr(
        det, "_auth_results_for_domain", lambda domain: {
            "has_mx": True,
            "spf_present": True,
            "dmarc_present": True,
            "dmarc_policy": "quarantine",
        }
    )
    payload = {
        "sender": "noreply@example.com",
        "receiver": "user@example.com",
        "subject": "Welcome",
        "body": "Your password will expire soon. Visit https://bit.ly/reset",
        "url": 1,
    }

    out = classify_email(payload)

    assert out.verdict in {"benign", "needs_review", "phishing"}
    assert isinstance(out.score, int)
    assert isinstance(out.reasons, list)
    assert isinstance(out.indicators, dict)
    assert hasattr(out.redactions, "types")
    assert hasattr(out, "redacted_body")


