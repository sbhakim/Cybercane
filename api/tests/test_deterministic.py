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


def test_extract_domain_handles_display_names():
    from app.pipeline.deterministic import _extract_domain
    assert _extract_domain("user@gmail.com") == "gmail.com"
    assert _extract_domain("Juan Miscaro <obao_fb@yahoo.ca>") == "yahoo.ca"
    assert _extract_domain('"Boumans, Jos" <hxh@DWIM.org>') == "dwim.org"
    assert _extract_domain("Absa <officialemail@absa.co.za>") == "absa.co.za"
    assert _extract_domain("no address here") == ""
    assert _extract_domain("") == ""


# ---------------------------------------------------------------- S3: opt-in standards-conformant auth checks
import dns.resolver as _r
from app.pipeline import deterministic as _D


class _Rd:
    def __init__(self, s): self.strings = [s.encode()]


def _fake_dns(table):
    """table maps (name, rdtype) -> list of TXT strings / True (record exists) / 'NX' / 'FAIL'."""
    def resolve(name, rdtype):
        v = table.get((name, rdtype))
        if v == "FAIL" or v is None and (name, "*") in table and table[(name, "*")] == "FAIL":
            raise _r.LifetimeTimeout() if hasattr(_r, "LifetimeTimeout") else _r.Timeout()
        if v == "NX":
            raise _r.NXDOMAIN()
        if v is None:
            raise _r.NoAnswer()
        return [_Rd(x) for x in v] if isinstance(v, list) else [object()]
    return resolve


def _score(monkeypatch, table, zone=None, policy="rfc"):
    monkeypatch.setattr(_D.dns.resolver, "resolve", _fake_dns(table))
    monkeypatch.setattr(_D.dns.resolver, "zone_for_name", lambda d: _r.dns.name.from_text(zone) if zone else (_ for _ in ()).throw(Exception("x")))
    return _D.score_email(sender="Alerts <a@alerts.example.com>", subject="Hi", body="Hello there.", url_flag=0,
                          enable_dns_checks=True, auth_policy=policy)


def test_strict_policy_is_default_and_unchanged(monkeypatch):
    t = {("alerts.example.com", "A"): True, ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"]}
    d_default = _score(monkeypatch, t, zone="example.com", policy="strict")
    assert d_default.indicators["has_mx"] is False and d_default.indicators["dmarc_present"] is False   # strict: no fallback
    assert "Sender domain missing MX record" in d_default.reasons


def test_rfc_implicit_mx_and_dmarc_org_fallback(monkeypatch):
    t = {("alerts.example.com", "A"): True, ("alerts.example.com", "TXT"): ["v=spf1 -all"],
         ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"]}
    d = _score(monkeypatch, t, zone="example.com")
    assert d.indicators["auth"]["has_mx"] is True and d.indicators["auth"].get("implicit_mx")
    assert d.indicators["auth"]["dmarc_present"] is True and d.indicators["auth"]["dmarc_from_org_domain"] == "example.com"
    assert d.indicators["dmarc_policy"] == "reject"
    assert not [r for r in d.reasons if "MX" in r or "DMARC" in r]


def test_rfc_failed_lookup_is_unknown_not_absent(monkeypatch):
    t = {(n, k): "FAIL" for n in ("alerts.example.com", "_dmarc.alerts.example.com") for k in ("MX", "A", "AAAA", "TXT")}
    d = _score(monkeypatch, t)
    assert d.indicators["auth"]["has_mx"] is None and d.indicators["auth"]["spf_present"] is None
    assert d.score == 0 and "MX could not be checked" in d.reasons


def test_rfc_nonexistent_domain_still_penalized(monkeypatch):
    t = {(n, k): "NX" for n in ("alerts.example.com", "_dmarc.alerts.example.com") for k in ("MX", "A", "AAAA", "TXT")}
    d = _score(monkeypatch, t)
    assert d.indicators["auth"]["has_mx"] is False and d.indicators["auth"]["dmarc_present"] is False
    assert "Sender domain missing MX record" in d.reasons
