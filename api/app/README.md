# FastAPI Application (Backend App)

This directory contains the HackUMBC backend application built with FastAPI. It exposes health and scanning endpoints and hosts the deterministic phishing detection pipeline with PII redaction.

## Highlights
- FastAPI app in `app/main.py` with CORS enabled for local dev
- Modular routers in `app/routers/`
- Deterministic pipeline in `app/pipeline/` with PII redaction and DNS/SPF/DMARC checks
- Pydantic schemas in `app/schemas.py`

## Run (via Docker Compose)
From repo root:
```bash
docker compose up --build api db
```
API: `http://localhost:8000`

Health: `GET /health`

## Run (local uvicorn)
In `api/`:
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Key Files
- `main.py`: creates FastAPI app, mounts routers
- `routers/health.py`: health endpoint
- `routers/scan.py`: scanning endpoint `POST /scan`
- `pipeline/`: redaction and deterministic scoring
- `schemas.py`: Pydantic models for input/output
 - `scripts/clean_data.py`: CSV cleaning (sender_email extraction, timestamp normalization)
 - `scripts/backfill_embeddings.py`: OpenAI embeddings backfill into pgvector columns

## Evaluation
- Pandas-based evaluation and dataset stats live in `app/evaluation/`.
- Run full evaluation on `datasets/Nazario.csv` and write CSV/JSON to `datasets/evaluation_results_[timestamp]`:
```bash
py -m app.evaluation.run | cat
```

## API
### POST /scan
Request body (JSON):
```json
{
  "sender": "someone@example.com",
  "receiver": "user@example.com",
  "subject": "Hello",
  "body": "Check this link https://bit.ly/x",
  "url": 1
}
```

Response body (JSON):
```json
{
  "verdict": "needs_review",
  "score": 3,
  "reasons": ["Shortened URL detected", "Urgency language detected"],
  "indicators": {"sender_domain": "example.com", "link_hosts": ["bit.ly"]},
  "redactions": {"types": {"email": 0, "phone": 0, "ssn": 0, "cc": 0, "dob": 0}, "count": 0},
  "redacted_body": "Check this link https://bit.ly/x"
}
```

## Pipeline Overview
Processing order for `POST /scan`:
1. Redact PII in body via `pipeline/pii.py`
2. Score deterministically via `pipeline/deterministic.py`:
   - Domain heuristics (freemail corporate claims, lookalikes)
   - URL heuristics (IP literal, shorteners)
   - Content cues (urgency, credential requests)
   - DNS checks (MX presence, SPF/DMARC TXT presence and DMARC policy)
3. Threshold to verdict: `benign | needs_review | phishing`

## Notes
- DNS checks use `dnspython` and query public DNS for MX/TXT; timeouts/errors are treated as missing records (conservative weighting).
- The rule weights live in `pipeline/deterministic.py` as `RULE_WEIGHTS` and can be adjusted in code.

## Database & Embeddings

### Schema (messages)
Backed by Postgres 17 + pgvector. Core columns:
- Raw: `sender`, `sender_email`, `receiver`, `msg_date`, `subject`, `body`, `url_extracted`
- Flags: `urls` (0/1), `label` (0/1), derived `sender_domain`, `has_url`
- RAG vectors (1536 dims): `subject_emb`, `body_emb`, `url_emb`, `doc_emb`

See `db/init.sql` for full DDL, triggers, and HNSW indexes.

### Ingestion (Nazario.csv)
1) Copy CSV into db container:
```bash
docker compose cp datasets/Nazario.clean.csv db:/tmp/Nazario.clean.csv
```
2) Ingest with COPY (NULL ''):
```bash
docker compose exec db psql -U postgres -d app -c "COPY messages (sender, receiver, msg_date, subject, body, urls, label, sender_email, url_extracted) FROM '/tmp/Nazario.clean.csv' WITH (FORMAT csv, HEADER true, NULL '');"
```

### Embeddings Backfill
Rebuild API to ensure `openai` is installed and `OPENAI_API_KEY` is set:
```bash
docker compose build api && docker compose up -d api
```

- Generate combined document embeddings (subject + body) → `doc_emb`:
```bash
docker compose exec api python -m app.scripts.backfill_embeddings --target doc --batch-size 64 --model text-embedding-3-small
```
- Optionally generate other embeddings:
```bash
docker compose exec api python -m app.scripts.backfill_embeddings --target subject --batch-size 64
docker compose exec api python -m app.scripts.backfill_embeddings --target body --batch-size 64
docker compose exec api python -m app.scripts.backfill_embeddings --target url --batch-size 64
```

### Current Embedding Status (after Nazario load)
- `doc_emb`: 1565
- `subject_emb`: 1561
- `body_emb`: pending (not backfilled)
- `url_emb`: 184

Verify counts:
```bash
docker compose exec db psql -U postgres -d app -c "SELECT COUNT(*) total, COUNT(doc_emb) doc, COUNT(subject_emb) subject, COUNT(body_emb) body, COUNT(url_emb) url FROM messages;"
```


