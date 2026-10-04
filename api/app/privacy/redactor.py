"""
Redactor v2.

Removes identifiers from email text before any external call. Compared with
`pipeline/pii.py` (v1, kept for Phase 1 display), v2:
  - masks identifiers fully (no retained digit tails),
  - covers dates, MRN/member/account IDs, ZIP codes, and street addresses,
  - optionally masks person names and locations with a local NER model,
  - keeps phishing signals: organization/brand names, URL hosts and paths,
    and email domains. URL query strings and fragments are dropped.

The redactor is a data-minimization step, not a certified de-identification
method; its recall is measured separately on annotated data.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

REDACTOR_VERSION = "2.3"

# ============================================================================
# Regex patterns (applied in order)
# ============================================================================

_URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"')\]]+", re.I)
# ASCII lookarounds instead of \b: \b fails next to CJK text, which Python treats as word characters.
_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z])")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_PHONE_RE = re.compile(r"(?<![A-Za-z])(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b")
_ID_LABELED_RE = re.compile(
    r"\b(MRN|medical record(?: number| no\.?)?|member(?: id| number| no\.?)?|"
    r"account(?: number| no\.?| #)?|policy(?: number| no\.?)?|patient id|claim(?: number| no\.?| #)?)"
    r"(\s*[:#]?\s*)([A-Z0-9-]{4,})",
    re.I,
)
_DATE_RE = re.compile(
    r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}|"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}|"
    # v2.3: day-first dates ("14 March 1987"), missed by v2.2 in the planted-identifier audit
    r"\d{1,2}(?:st|nd|rd|th)?\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?,?\s+\d{4})\b",
    re.I,
)
_ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+(?:[A-Z][a-z]+\.?\s+){1,3}"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Parkway|Pkwy|"
    # v2.3: suffixes missed by v2.2 in the planted-identifier audit, plus common relatives
    r"Circle|Cir|Highway|Hwy|Trail|Trl|Square|Sq|Loop|Pike|Crescent|Plaza|Expressway|Freeway)\b\.?",
)
_ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
# v2.3: bare IPv4 addresses in prose (v2.2 had no IP rule). URLs are stashed before
# patterns run, so IP hosts inside URLs, a phishing signal, are kept.
# Boundaries reject an adjacent digit or a dot-digit continuation (version strings such as
# 1.2.3.4.5) but allow sentence punctuation: "(?![\d.])" missed every sentence-final IP.
_IP_RE = re.compile(r"(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)(?!\.\d)")
# Any token containing 6+ consecutive digits (tracking, account, and case numbers).
_LONG_DIGITS_RE = re.compile(r"[A-Za-z0-9]*\d{6,}[A-Za-z0-9]*")

_PLACEHOLDER_RE = re.compile(r"⟦U(\d+)⟧")


@dataclass
class RedactionReport:
    version: str = REDACTOR_VERSION
    counts: Dict[str, int] = field(default_factory=dict)
    ner_used: bool = False

    def add(self, key: str, n: int = 1) -> None:
        if n:
            self.counts[key] = self.counts.get(key, 0) + n

    @property
    def total(self) -> int:
        return sum(self.counts.values())


# ============================================================================
# Optional local NER (person names, locations)
# ============================================================================

_NER = None
_NER_FAILED = False
NER_MODEL = os.getenv("CYBERCANE_NER_MODEL", "dslim/bert-base-NER")
_NER_LABELS = {"PER": "[NAME]", "LOC": "[LOCATION]"}
_NER_MIN_SCORE = 0.70
_NER_WINDOW = 1500  # characters per NER call


def _get_ner():
    global _NER, _NER_FAILED
    if _NER is not None or _NER_FAILED:
        return _NER
    if os.getenv("CYBERCANE_DISABLE_NER", "").strip() == "1":
        _NER_FAILED = True
        return None
    try:
        from transformers import pipeline  # local model; no network at inference

        # CPU by default; the GPU is used only when explicitly requested.
        device = 0 if os.getenv("CYBERCANE_NER_DEVICE", "cpu").strip().lower() == "cuda" else -1
        _NER = pipeline("ner", model=NER_MODEL, aggregation_strategy="simple", device=device)
    except Exception as exc:
        logger.warning("Local NER unavailable (%s); redaction falls back to patterns only", exc)
        _NER_FAILED = True
    return _NER


def _ner_spans(text: str) -> List[Tuple[int, int, str]]:
    ner = _get_ner()
    if ner is None or not text:
        return []
    spans: List[Tuple[int, int, str]] = []
    for start in range(0, len(text), _NER_WINDOW):
        chunk = text[start:start + _NER_WINDOW]
        for ent in ner(chunk):
            tag = _NER_LABELS.get(ent.get("entity_group"))
            if tag and float(ent.get("score", 0)) >= _NER_MIN_SCORE:
                spans.append((start + int(ent["start"]), start + int(ent["end"]), tag))
    # Merge overlapping or adjacent spans that share a tag (subword splits).
    spans.sort()
    merged: List[Tuple[int, int, str]] = []
    for s, e, t in spans:
        if merged and merged[-1][2] == t and s <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e), t)
        else:
            merged.append((s, e, t))
    return merged


# ============================================================================
# Public API
# ============================================================================

_URL_USERINFO_RE = re.compile(r"^((?:https?://)?)[^/@\s]+@", re.I)
_URL_DIGITS_RE = re.compile(r"\d{6,}")


def _sanitize_url(url: str) -> str:
    """
    Keep scheme, host, and path (phishing signals). Drop query and fragment,
    mask userinfo (keeping the fact that it exists, a known deception trick),
    and mask long digit runs in the path (tracking or account identifiers).
    """
    base = re.split(r"[?#]", url, maxsplit=1)[0]
    had_query = len(base) < len(url)
    base = _URL_USERINFO_RE.sub(r"\1[USERINFO]@", base)
    base = _URL_DIGITS_RE.sub("[ID]", base)
    base = _EMAIL_RE.sub(lambda m: f"[EMAIL]@{m.group(1)}", base)
    return base + ("?[QUERY]" if had_query else "")


def redact_v2(text: Optional[str], *, use_ner: bool = True) -> Tuple[str, RedactionReport]:
    report = RedactionReport()
    if not text:
        return "", report

    # 1. Protect URLs behind placeholders so digit patterns do not mangle hosts.
    urls: List[str] = []

    def _stash(m: re.Match) -> str:
        urls.append(_sanitize_url(m.group(0)))
        return f"⟦U{len(urls) - 1}⟧"

    s = _URL_RE.sub(_stash, text)
    report.add("url_query_dropped", sum(1 for u in urls if u.endswith("?[QUERY]")))

    def _sub(pattern: re.Pattern, repl, key: str, value: str) -> str:
        out, n = pattern.subn(repl, value)
        report.add(key, n)
        return out

    s = _sub(_EMAIL_RE, lambda m: f"[EMAIL]@{m.group(1)}", "email", s)
    s = _sub(_SSN_RE, "[SSN]", "ssn", s)
    s = _sub(_IP_RE, "[IP]", "ip", s)
    s = _sub(_ID_LABELED_RE, lambda m: f"{m.group(1)}{m.group(2)}[ID]", "id", s)
    s = _sub(_CC_RE, "[CARD]", "card", s)
    s = _sub(_PHONE_RE, "[PHONE]", "phone", s)
    s = _sub(_DATE_RE, "[DATE]", "date", s)
    s = _sub(_ADDRESS_RE, "[ADDRESS]", "address", s)
    s = _sub(_ZIP_RE, "[ZIP]", "zip", s)
    s = _sub(_LONG_DIGITS_RE, "[ID]", "id", s)

    # 2. Local NER for names and locations.
    if use_ner:
        spans = _ner_spans(s)
        report.ner_used = _NER is not None
        for start, end, tag in reversed(spans):
            if _PLACEHOLDER_RE.search(s[start:end]) or s[start:end].startswith("["):
                continue
            s = s[:start] + tag + s[end:]
            report.add(tag.strip("[]").lower())

    # 3. Restore sanitized URLs.
    s = _PLACEHOLDER_RE.sub(lambda m: urls[int(m.group(1))], s)
    return s, report
