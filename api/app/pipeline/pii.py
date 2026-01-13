
"""
Phase 1: PII redaction utilities.

This module provides a minimal, deterministic PII detector and masker. The
patterns are intentionally conservative, favoring simple redaction over
perfect coverage. Raw PII is never returned.
"""

import re
from typing import Dict, Tuple

# ============================================================================
# Regex Patterns
# ============================================================================

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_DOB_RE = re.compile(r"\b(?:\d{1,2}[/-]){2}\d{2,4}\b")


def _mask_email(value: str) -> str:
    """Mask an email address while preserving the domain."""
    local, _, domain = value.partition("@")
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + ("*" * (len(local) - 2)) + local[-1]
    return f"{masked_local}@{domain}"


def _mask_digits_tail(value: str, keep: int = 4) -> str:
    """Mask all but the last digits while preserving formatting."""
    digits = [c for c in value if c.isdigit()]
    if len(digits) <= keep:
        return "*" * len(value)
    masked = []
    seen = 0
    for c in reversed(value):
        if c.isdigit() and seen < keep:
            masked.append(c)
            seen += 1
        elif c.isdigit():
            masked.append("*")
        else:
            masked.append(c)
    return "".join(reversed(masked))


def redact(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Redact common PII patterns and return redacted text + per-type counts.
    """
    counts: Dict[str, int] = {"email": 0, "phone": 0, "ssn": 0, "cc": 0, "dob": 0}

    def sub_and_count(pattern: re.Pattern, repl_func, key: str, s: str) -> str:
        def _repl(m: re.Match) -> str:
            nonlocal counts
            counts[key] += 1
            return repl_func(m.group(0))

        return pattern.sub(_repl, s)

    red = sub_and_count(_EMAIL_RE, _mask_email, "email", text)
    red = sub_and_count(_PHONE_RE, lambda v: _mask_digits_tail(v, 4), "phone", red)
    red = sub_and_count(_SSN_RE, lambda v: "***-**-" + v[-4:], "ssn", red)
    red = sub_and_count(_CC_RE, lambda v: _mask_digits_tail(v, 4), "cc", red)
    red = sub_and_count(_DOB_RE, lambda v: "**/**/****", "dob", red)

    return red, counts


def redact_text(text: str | None) -> str:
    """Convenience wrapper that returns only the redacted string."""
    if not text:
        return ""
    redacted, _ = redact(text)
    return redacted
