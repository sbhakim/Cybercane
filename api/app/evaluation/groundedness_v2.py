"""
Evidence-based groundedness checker.

Each tagged explanation bullet is checked against the stored evidence of the
analysis (Phase 1 indicators, redacted body, retrieved neighbor similarities,
asserted ontology classes), not against keywords alone:

  SUPPORTED    every checkable claim in the bullet matches the evidence
  UNSUPPORTED  at least one claim contradicts the evidence, or cites
               evidence that does not exist (e.g. similarity with no neighbors)
  UNKNOWN      the bullet makes no claim this checker can verify

The v1 checker (groundedness.py) is kept only to reproduce historical tables.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, List

SIM_TOLERANCE = 0.01

_NUM_RE = re.compile(r"(?<![\d.])(0?\.\d+|1\.0+)(?![\d.])")
_NEG = r"(?:no|missing|lack(?:s|ing)?(?: of)?|absent|without|not present|fails?|failed|none)"
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_QUOTED_RE = re.compile(r"[\"'“‘]([^\"'”’]{2,40})[\"'”’]")


@lru_cache(maxsize=1)
def _known_classes() -> Dict[str, str]:
    """Lower-cased surface forms (CamelCase and spaced) -> ontology class name."""
    from app.symbolic.ontology_reasoner import PhishingOntologyReasoner

    r = PhishingOntologyReasoner()
    names = set(r._rules) | {r._uri_to_name(u) for u in r._attack_types}
    forms = {}
    for n in names:
        forms[n.lower()] = n
        forms[re.sub(r"(?<!^)([A-Z])", r" \1", n).lower()] = n
    return forms


def check_similarity(reason: str, neighbors: List[Dict]) -> str:
    sims = [float(n["similarity"]) for n in neighbors if n.get("similarity") is not None]
    if not sims:
        return "UNSUPPORTED"  # similarity claimed but nothing was retrieved
    s = sorted(sims, reverse=True)
    stats = s + [sum(s[:3]) / len(s[:3]), sum(s) / len(s)]
    nums = [float(x) for x in _NUM_RE.findall(reason)]
    if not nums:
        return "UNKNOWN"
    ok = all(any(abs(x - v) <= SIM_TOLERANCE for v in stats) for x in nums)
    return "SUPPORTED" if ok else "UNSUPPORTED"


def check_ontology(reason: str, analysis: Dict) -> str:
    asserted = {a["attack_type"] for a in (analysis.get("ontology_attacks") or [])}
    low = reason.lower()
    mentioned = {cls for form, cls in _known_classes().items() if form and form in low}
    if not mentioned:
        return "UNKNOWN"
    return "SUPPORTED" if mentioned <= asserted else "UNSUPPORTED"


def check_auth(reason: str, ind: Dict) -> str:
    low = reason.lower()
    claims = {k: bool(re.search(rf"{_NEG}[^.;]{{0,20}}\b{k}\b|\b{k}\b[^.;]{{0,20}}{_NEG}", low))
              for k in ("mx", "spf", "dmarc")}
    policy = re.search(r"dmarc[^.;]{0,20}(?:policy|p=)[^.;]{0,5}\b(none|quarantine|reject)\b", low)
    if not any(claims.values()) and not policy:
        return "UNKNOWN"
    if "has_mx" not in ind:
        return "UNKNOWN"  # DNS evidence unavailable: claim cannot be checked
    truth = {"mx": not ind.get("has_mx", True), "spf": not ind.get("spf_present", True),
             "dmarc": not ind.get("dmarc_present", True)}
    if any(claimed and not truth[k] for k, claimed in claims.items()):
        return "UNSUPPORTED"
    if policy and policy.group(1) != str(ind.get("dmarc_policy", "none")).lower():
        return "UNSUPPORTED"
    return "SUPPORTED"


def check_url(reason: str, ind: Dict) -> str:
    low = reason.lower()
    checks = []
    if _IP_RE.search(reason) or "ip literal" in low or "ip address" in low:
        checks.append(bool(ind.get("ip_literal_link")))
    if any(k in low for k in ("shorten", "short link", "bit.ly", "tinyurl")):
        checks.append(bool(ind.get("shortened_url")))
    if any(k in low for k in ("mismatch", "lookalike", "does not match", "doesn't match")):
        checks.append(bool(ind.get("domain_mismatch") or ind.get("lookalike")))
    hosts = {h.lower() for h in (ind.get("link_hosts") or [])}
    cited = {h.lower() for h in _HOST_RE.findall(reason)} - {ind.get("sender_domain", "").lower()}
    if cited:
        checks.append(all(any(c == h or h.endswith("." + c) or c.endswith("." + h) for h in hosts) for c in cited))
    if not checks:
        return "UNKNOWN"
    return "SUPPORTED" if all(checks) else "UNSUPPORTED"


def check_urgency(reason: str, ind: Dict, body: str) -> str:
    if not ind.get("urgency"):
        return "UNSUPPORTED"  # urgency claimed, none detected
    # Any quoted phrase must actually occur in the email.
    quoted = [q.lower().strip() for q in _QUOTED_RE.findall(reason)]
    if quoted and not all(q in (body or "").lower() for q in quoted):
        return "UNSUPPORTED"  # quotes a phrase that is not in the email
    return "SUPPORTED"


def check_content(reason: str, ind: Dict) -> str:
    low = reason.lower()
    if any(k in low for k in ("credential", "password", "login", "log in", "sign in", "verify your account")):
        return "SUPPORTED" if ind.get("creds_request") else "UNSUPPORTED"
    return "UNKNOWN"


def evaluate_groundedness_v2(reason: str, tag: str, analysis: Dict) -> str:
    phase1 = analysis.get("phase1", {}) or {}
    ind = phase1.get("indicators", {}) or {}
    if tag == "SIMILARITY":
        return check_similarity(reason, analysis.get("neighbors", []) or [])
    if tag == "ONTOLOGY":
        return check_ontology(reason, analysis)
    if tag == "AUTH":
        return check_auth(reason, ind)
    if tag == "URL":
        return check_url(reason, ind)
    if tag == "URGENCY":
        return check_urgency(reason, ind, phase1.get("redacted_body", ""))
    if tag == "CONTENT":
        return check_content(reason, ind)
    return "UNKNOWN"
