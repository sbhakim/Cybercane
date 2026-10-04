"""
Phase 1: Deterministic (rule-based) phishing scoring.

This module implements lightweight, explainable heuristics that operate fully
offline. DNS/auth lookups are optional and can be disabled for tests or offline
evaluation. The output is a stable set of reasons and indicators that the UI
can display without interpretation.
"""

import dns.exception
import dns.resolver
from email.utils import parseaddr
import re
from dataclasses import dataclass
from typing import Any, Dict, List

# ============================================================================
# Rule Inputs and Patterns
# ============================================================================

FREEMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "proton.me",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "buff.ly",
}

URGENCY_KEYWORDS = {
    "urgent",
    "immediate action",
    "verify your account",
    "password expires",
    "suspend",
    "pay now",
    "update your information",
}

CREDENTIAL_PATTERNS = [
    re.compile(r"\bpasswords?\b", re.IGNORECASE),
    re.compile(r"\blog\s*in\b", re.IGNORECASE),
    re.compile(r"\blogin\b", re.IGNORECASE),
    re.compile(r"\bssn\b", re.IGNORECASE),
    re.compile(r"\bsocial\s+security\b", re.IGNORECASE),
    re.compile(r"\bcredit\s+cards?\b", re.IGNORECASE),
    re.compile(r"\bbank\s+accounts?\b", re.IGNORECASE),
]

REQUEST_VERB_PATTERNS = [
    re.compile(r"\b(enter|provide|send|share|confirm|verify|update|reset|submit)\b", re.IGNORECASE),
]


# Very lightweight URL host extraction; avoids heavy parsing dependencies.
_URL_HOST_RE = re.compile(r"(?:https?://|www\.)([^/\s]+)")
_IP_LIT_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ============================================================================
# Helper Functions
# ============================================================================

def _extract_domain(addr: str) -> str:
    """Extract the domain from a sender, plain or display-name form ('Name <user@host>'); "" on malformed input."""
    _, email_addr = parseaddr(addr or "")
    if "@" not in email_addr:
        return ""
    return email_addr.rsplit("@", 1)[1].lower().strip().strip(".>")


def _hosts_in_text(text: str) -> List[str]:
    """Best-effort host extraction for heuristics (not a full RFC parser)."""
    hosts: List[str] = []
    for m in _URL_HOST_RE.finditer(text):
        host = m.group(1).lower()
        # Strip brackets for IPv6 literals and drop ports.
        host = host.split(":")[0].strip("[]")
        hosts.append(host)
    return hosts


def _normalize_host(host: str) -> str:
    """Normalize host for comparison (strip www)."""
    host = host.lower().strip()
    if host.startswith("www."):
        return host[4:]
    return host


def _host_matches_sender(host: str, sender_domain: str) -> bool:
    """Return True if host is sender domain or a subdomain thereof."""
    if not sender_domain:
        return False
    host = _normalize_host(host)
    sender_domain = _normalize_host(sender_domain)
    return host == sender_domain or host.endswith("." + sender_domain)


def _is_confusable(a: str, b: str) -> bool:
    """
    Minimal confusable check using common character substitutions.

    This is intentionally lightweight; the goal is to flag obvious lookalikes
    without pulling in heavier dependency chains.
    """
    simple_map = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"})
    na = a.translate(simple_map)
    nb = b.translate(simple_map)
    return na == nb and a != b


def _has_mx(domain: str) -> bool:
    """Return True if domain publishes MX records; treat errors as missing."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return len(answers) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
        return False


def _spf_record(domain: str) -> str | None:
    """Return SPF TXT record value if present, else None."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", "ignore") if hasattr(rdata, "strings") else str(rdata)
            if txt.lower().startswith("v=spf1"):
                return txt
    except Exception:
        return None
    return None


def _dmarc_record(domain: str) -> str | None:
    """Return DMARC TXT record value if present, else None."""
    query = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(query, "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", "ignore") if hasattr(rdata, "strings") else str(rdata)
            if txt.lower().startswith("v=dmarc1"):
                return txt
    except Exception:
        return None
    return None


def _parse_dmarc_policy(txt: str | None) -> str | None:
    """Extract the DMARC policy (p=) directive from a DMARC TXT record."""
    if not txt:
        return None
    parts = [p.strip() for p in txt.split(";")]
    for p in parts:
        if p.startswith("p="):
            return p.split("=", 1)[1]
    return None


_LOOKUP_FAILED = "unknown"


def _rfc_lookup(name: str, rdtype: str):
    """Resolve name/rdtype. Returns answers, None when the name or type is absent (NXDOMAIN / NoAnswer),
    or _LOOKUP_FAILED when no authoritative answer was obtained (timeout, SERVFAIL, no nameservers)."""
    try:
        return dns.resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except Exception:
        return _LOOKUP_FAILED


def _txt_with_prefix(answers, prefix: str) -> str | None:
    for rdata in answers or []:
        txt = b"".join(rdata.strings).decode("utf-8", "ignore") if hasattr(rdata, "strings") else str(rdata)
        if txt.lower().startswith(prefix):
            return txt
    return None


def _org_zone(domain: str) -> str | None:
    """Organizational zone of a domain via its zone cut (public-suffix-free approximation)."""
    try:
        z = dns.resolver.zone_for_name(domain).to_text().rstrip(".").lower()
        return z if z and z != domain and domain.endswith("." + z) else None
    except Exception:
        return None


def _auth_results_rfc(domain: str) -> Dict[str, Any]:
    """Standards-conformant variant (S3): implicit MX (RFC 5321 §5.1), DMARC organizational-domain fallback
    (RFC 7489 §6.6.3), failed lookups reported as unknown rather than absent. SPF is per-domain (RFC 7208)."""
    out: Dict[str, Any] = {"policy": "rfc", "unknown": []}
    mx = _rfc_lookup(domain, "MX")
    if mx is _LOOKUP_FAILED:
        out["has_mx"] = None; out["unknown"].append("mx")
    elif mx:
        out["has_mx"] = True
    else:
        a = _rfc_lookup(domain, "A"); aaaa = None if a and a is not _LOOKUP_FAILED else _rfc_lookup(domain, "AAAA")
        if (a and a is not _LOOKUP_FAILED) or (aaaa and aaaa is not _LOOKUP_FAILED):
            out["has_mx"] = True; out["implicit_mx"] = True
        elif a is _LOOKUP_FAILED and aaaa is _LOOKUP_FAILED:
            out["has_mx"] = None; out["unknown"].append("mx")
        else:
            out["has_mx"] = False
    txt = _rfc_lookup(domain, "TXT")
    if txt is _LOOKUP_FAILED:
        out["spf_present"] = None; out["unknown"].append("spf")
    else:
        out["spf_present"] = bool(_txt_with_prefix(txt, "v=spf1"))
    d = _rfc_lookup(f"_dmarc.{domain}", "TXT")
    rec = None if d is _LOOKUP_FAILED else _txt_with_prefix(d, "v=dmarc1")
    if rec is None:
        org = _org_zone(domain)
        if org:
            d2 = _rfc_lookup(f"_dmarc.{org}", "TXT")
            rec = None if d2 is _LOOKUP_FAILED else _txt_with_prefix(d2, "v=dmarc1")
            if rec:
                out["dmarc_from_org_domain"] = org
    if rec is None and d is _LOOKUP_FAILED:
        out["dmarc_present"] = None; out["unknown"].append("dmarc")
    else:
        out["dmarc_present"] = bool(rec)
    out["dmarc_policy"] = _parse_dmarc_policy(rec) or "none"
    return out


def _auth_results_for_domain(domain: str, policy: str = "strict") -> Dict[str, Any]:
    """Run MX/SPF/DMARC lookups and return a normalized auth summary."""
    if policy == "rfc":
        return _auth_results_rfc(domain)
    has_mx = _has_mx(domain)
    spf = _spf_record(domain)
    dmarc = _dmarc_record(domain)
    dmarc_policy = _parse_dmarc_policy(dmarc)
    return {
        "has_mx": has_mx,
        "spf_present": bool(spf),
        "dmarc_present": bool(dmarc),
        "dmarc_policy": dmarc_policy or "none",
    }


@dataclass
class Decision:
    verdict: str
    score: int
    reasons: List[str]
    indicators: Dict[str, Any]


# ============================================================================
# Rule Weights and Scoring
# ============================================================================

# Tuneable weights; thresholds at the end convert score -> verdict.
# Updated weights based on ablation analysis (see error_reason_summary.tex):
# - Removed "url_present" (contributed to 40% of FPs, low discriminative power)
# - Increased urgency and creds_request (stronger phishing signals)
RULE_WEIGHTS: Dict[str, int] = {
    "freemail_brand_claim": 2,
    "lookalike_domain": 2,
    "ip_literal_link": 2,
    "shortened_url": 2,        # Increased from 1: specific URL threat pattern
    "urgency": 2,              # Increased from 1: strong social engineering signal
    "creds_request": 2,        # Increased from 1: strong phishing indicator
    "missing_mx": 2,
    "no_spf": 2,
    "no_dmarc": 1,
    "strict_dmarc_missing_align": 3,
    # REMOVED: "url_present": 1  (ablation showed non-discriminative)
}


def score_email(*, sender: str, subject: str, body: str, url_flag: int,
                allowed_brand_domains: List[str] | None = None,
                rule_weights: Dict[str, int] | None = None,
                enable_dns_checks: bool = True,
                auth_policy: str = "strict") -> Decision:
    """
    Score an email using deterministic rules and return verdict + reasons.

    Args:
        sender: Sender address or display string with email
        subject: Email subject
        body: Email body content (redacted upstream)
        url_flag: 1 if message contains links (dataset semantics), else 0
        allowed_brand_domains: Optional brand allowlist for lookalike checks
        rule_weights: Optional override for RULE_WEIGHTS
        enable_dns_checks: Toggle MX/SPF/DMARC lookups (tests/offline)
        auth_policy: "strict" (default, unchanged) or "rfc" (S3: implicit MX, DMARC org-domain fallback,
            failed lookups treated as unknown)

    Returns:
        Decision with verdict, numeric score, reasons, and indicators map
    """
    allowed_brand_domains = allowed_brand_domains or []
    weights = rule_weights or RULE_WEIGHTS
    reasons: List[str] = []
    indicators: Dict[str, Any] = {}
    score = 0

    sender_domain = _extract_domain(sender)
    indicators["sender_domain"] = sender_domain
    if sender_domain in FREEMAIL_DOMAINS:
        indicators["freemail_sender"] = True

    # DNS/Auth checks (optional, best-effort)
    auth: Dict[str, Any] = {"has_mx": None, "spf_present": None, "dmarc_present": None, "dmarc_policy": None}
    if enable_dns_checks and sender_domain:
        auth = _auth_results_for_domain(sender_domain) if auth_policy == "strict" else _auth_results_for_domain(sender_domain, auth_policy)
        indicators["auth"] = auth
        # Flatten for UI consumption
        indicators["has_mx"] = bool(auth.get("has_mx"))
        indicators["spf_present"] = bool(auth.get("spf_present"))
        indicators["dmarc_present"] = bool(auth.get("dmarc_present"))
        indicators["dmarc_policy"] = auth.get("dmarc_policy") or "none"
        if auth_policy == "rfc":                               # S3: "unknown" (None) is not penalized
            for key, w, msg in (("has_mx", "missing_mx", "Sender domain missing MX record"),
                                ("spf_present", "no_spf", "SPF not present for sender domain"),
                                ("dmarc_present", "no_dmarc", "DMARC not present for sender domain")):
                if auth.get(key) is False:
                    score += weights.get(w, 0); reasons.append(msg)
                elif auth.get(key) is None:
                    reasons.append(f"{msg.split(' ')[0] if key != 'has_mx' else 'MX'} could not be checked")
        else:
            if not auth.get("has_mx"):
                score += weights.get("missing_mx", 0)
                reasons.append("Sender domain missing MX record")
            if not auth.get("spf_present"):
                score += weights.get("no_spf", 0)
                reasons.append("SPF not present for sender domain")
            if not auth.get("dmarc_present"):
                score += weights.get("no_dmarc", 0)
                reasons.append("DMARC not present for sender domain")

    # 1) Freemail claiming corporate brand
    if sender_domain in FREEMAIL_DOMAINS:
        for brand in allowed_brand_domains:
            if brand in subject.lower() or brand in body.lower():
                score += weights.get("freemail_brand_claim", 0)
                reasons.append("Freemail sender claims corporate brand")
                indicators["freemail_brand_claim"] = True
                break

    # 2) Lookalike domains (basic confusables)
    for brand in allowed_brand_domains:
        if _is_confusable(sender_domain, brand):
            score += weights.get("lookalike_domain", 0)
            reasons.append("Sender domain looks like brand domain (confusable)")
            indicators.setdefault("lookalike", []).append({"sender": sender_domain, "brand": brand})
            break

    # 3) URL-based checks if url_flag indicates links
    if url_flag == 1:
        # Preserve backward-compatibility if callers still pass "url_present".
        if "url_present" in weights:
            score += weights.get("url_present", 0)
            reasons.append("URL present in email")
            indicators["url_present"] = True
        # URL presence alone is not discriminative; focus on specific URL threats.
        hosts = _hosts_in_text(body)
        indicators["link_hosts"] = hosts
        domain_mismatch = False
        for h in hosts:
            if _IP_LIT_RE.match(h):
                score += weights.get("ip_literal_link", 0)
                reasons.append("Link points to IP literal host")
                indicators["ip_literal_link"] = True
            if any(h.endswith(s) for s in URL_SHORTENERS):
                score += weights.get("shortened_url", 0)
                reasons.append("Shortened URL detected")
                indicators["shortened_url"] = True
            if sender_domain and not _IP_LIT_RE.match(h) and not _host_matches_sender(h, sender_domain):
                domain_mismatch = True
        if domain_mismatch:
            indicators["domain_mismatch"] = True

    # 4) Content cues: urgency + credentials
    low_body = body.lower()
    if any(k in low_body for k in URGENCY_KEYWORDS):
        score += weights.get("urgency", 0)
        reasons.append("Urgency language detected")
        indicators["urgency"] = True

    creds_hit = any(p.search(body) for p in CREDENTIAL_PATTERNS)
    request_hit = any(p.search(body) for p in REQUEST_VERB_PATTERNS)
    if creds_hit and request_hit:
        score += weights.get("creds_request", 0)
        reasons.append("Credentials/PII request language detected")
        indicators["creds_request"] = True

    # Thresholds per PLAN.md
    if score < 2:
        verdict = "benign"
    elif score < 5:
        verdict = "needs_review"
    else:
        verdict = "phishing"

    return Decision(verdict=verdict, score=score, reasons=reasons, indicators=indicators)
