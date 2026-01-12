# Pipeline Modules

Deterministic, privacy-first email scanning pipeline. All processing runs locally in the API.

## Modules
- `pii.py`: Regex-based PII redaction. Masks emails, phone, SSN, credit cards, DOB. Returns redacted text and counts per PII type.
- `deterministic.py`: Rule-based scorer. Uses domain/url/content heuristics and DNS (MX/SPF/DMARC) presence checks. Central weights in `RULE_WEIGHTS`.
- `classify.py`: Orchestrator used by `/scan`. Runs redaction first, then scoring, and returns a structured response.

## Scoring Overview
Signals and their typical weights (see `RULE_WEIGHTS` for exact values):
- Freemail + corporate brand claim: medium
- Lookalike sender domain (basic confusable mapping): medium
- Link host is IP literal: medium
- URL shortener detected: low
- Urgency phrasing: low
- Credential/PII request language: low
- DNS: missing MX (medium), no SPF (medium), no DMARC (low); DMARC policy parsed and exposed for future stricter logic

Thresholds:
- `< 2` → benign
- `2–4` → needs_review
- `>= 5` → phishing

## DNS/Auth Checks
Uses `dnspython` to query:
- MX for sender domain
- TXT for SPF (`v=spf1`)
- TXT for DMARC (`_dmarc.domain`, `v=dmarc1`) and policy `p=`
Errors/timeouts are treated as missing records.

## Extensibility
- Add new rule: implement check function and adjust `RULE_WEIGHTS`.
- Integrate org policies: pass brand domains into `score_email(..., allowed_brand_domains=[...])`.
- Future: add ARC/DKIM verification for raw RFC822 messages when available.


