from app.pipeline.deterministic import score_email


def test_scoring_without_dns_checks_basic_thresholds():
    # Benign: no signals
    d1 = score_email(
        sender="alice@example.com",
        subject="Hello",
        body="Just checking in.",
        url_flag=0,
        allowed_brand_domains=["usaa.com"],
        enable_dns_checks=False,
    )
    assert d1.verdict == "benign"
    assert d1.score >= 0

    # Needs review: shortened url + urgency
    d2 = score_email(
        sender="bob@example.com",
        subject="urgent: action required",
        body="Click https://bit.ly/abc to proceed",
        url_flag=1,
        enable_dns_checks=False,
    )
    assert d2.score >= 2
    assert d2.verdict in {"needs_review", "phishing"}

    # Phishing: multiple signals
    d3 = score_email(
        sender="support@gmail.com",
        subject="Verify your account now",
        body="We need your password to update your bank account.",
        url_flag=0,
        allowed_brand_domains=["acme.com"],
        enable_dns_checks=False,
    )
    assert d3.score >= 5 or d3.verdict in {"needs_review", "phishing"}


def test_scoring_link_host_indicators():
    d = score_email(
        sender="alerts@corp.com",
        subject="",
        body="Visit https://192.168.1.1/login and https://tinyurl.com/x",
        url_flag=1,
        enable_dns_checks=False,
    )
    assert "link_hosts" in d.indicators
    assert any(h == "192.168.1.1" for h in d.indicators["link_hosts"])
    assert d.indicators.get("ip_literal_link") is True
    assert d.indicators.get("shortened_url") is True


def test_domain_mismatch_indicator():
    d = score_email(
        sender="alerts@corp.com",
        subject="",
        body="Visit https://evil.com/login",
        url_flag=1,
        enable_dns_checks=False,
    )
    assert d.indicators.get("domain_mismatch") is True
