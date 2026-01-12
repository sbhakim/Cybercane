# Routers

Modular FastAPI routers mounted in `app/main.py`.

## Endpoints

### GET /health
Response:
```json
{ "status": "ok", "db": true }
```

### POST /scan
Scans a single email payload using redaction-first deterministic rules.

Request body:
```json
{
  "sender": "someone@example.com",
  "receiver": "user@example.com",
  "subject": "Hello",
  "body": "Please verify your account at https://bit.ly/x",
  "url": 1
}
```

Response body:
```json
{
  "verdict": "needs_review",
  "score": 3,
  "reasons": ["Shortened URL detected", "Urgency language detected"],
  "indicators": {
    "sender_domain": "example.com",
    "link_hosts": ["bit.ly"],
    "auth": {"has_mx": true, "spf_present": false, "dmarc_present": false, "dmarc_policy": "none"}
  },
  "redactions": {"types": {"email": 0, "phone": 0, "ssn": 0, "cc": 0, "dob": 0}, "count": 0},
  "redacted_body": "Please verify your account at https://bit.ly/x"
}
```

Mounted prefixes (see `app/main.py`):
- `/health` → health router
- `/scan` → scan router


