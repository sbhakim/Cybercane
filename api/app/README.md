# Backend Application (FastAPI)

Research backend for CyberCane. This service exposes the Phase 1 deterministic
pipeline and the Phase 2 RAG analysis used in experiments, ablations, and
evaluation runs.

## Highlights

- FastAPI app entrypoint in `app/main.py`
- Modular routers under `app/routers/`
- Deterministic pipeline in `app/pipeline/` with PII redaction and DNS checks
- RAG service in `app/ai_service/` with provider fallback and thresholded verdicts
- Ontology reasoning in `app/symbolic/` for attack-type inference
- Pydantic schemas in `app/schemas.py`

## Run (Docker Compose)

From repo root:

```bash
docker compose up --build api db
```

API: `http://localhost:8000`  
Health: `GET /health`

## Run (Local uvicorn)

From `api/`:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Key Modules

- `main.py`: FastAPI app, routers, OpenAPI metadata
- `routers/health.py`: service + DB liveness
- `routers/scan.py`: Phase 1 endpoint (`POST /scan`)
- `routers/ai.py`: Phase 2 endpoint (`POST /ai/analyze`)
- `pipeline/`: redaction + deterministic scoring
- `ai_service/service.py`: embeddings, pgvector retrieval, similarity thresholds, LLM explanations
- `symbolic/ontology_reasoner.py`: PhishOnt inference + explanation chains
- `schemas.py`: request/response contracts
- `scripts/clean_data.py`: CSV normalization for ingestion
- `scripts/backfill_embeddings.py`: OpenAI embeddings backfill into pgvector

## Evaluation

Pandas-based evaluation scripts live in `app/evaluation/`.

Run a full evaluation on `datasets/Nazario.csv` and write CSV/JSON outputs to
`datasets/evaluation_results_[timestamp]`:

```bash
py -m app.evaluation.run | cat
```

## API

### POST /scan (Phase 1)

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

### POST /ai/analyze (Phase 1 + Phase 2)

Runs deterministic scoring, retrieval, and LLM explanation generation. Responses
include `ai_verdict`, `ai_score`, neighbor summaries, and optional ontology hits.

## Pipeline Overview

Processing order for `POST /scan`:

1. Redact PII in body via `pipeline/pii.py`
2. Score deterministically via `pipeline/deterministic.py`:
   - Domain heuristics (freemail corporate claims, lookalikes)
   - URL heuristics (IP literal, shorteners)
   - Content cues (urgency, credential requests)
   - DNS checks (MX presence, SPF/DMARC TXT presence and DMARC policy)
3. Threshold to verdict: `benign | needs_review | phishing`

Notes:
- DNS checks use `dnspython` and query public DNS for MX/TXT; timeouts/errors
  are treated as missing records (conservative weighting).
- Rule weights live in `pipeline/deterministic.py` as `RULE_WEIGHTS`.
- Phase 2 uses text-embedding-3-small for embeddings and GPT-4.1-mini for
  explanations by default (DeepSeek fallback supported).
- Similarity thresholds load from `datasets/best_thresholds_dataphish.json` if present
  or from `THRESHOLD_CONFIG_PATH`.

## Database and Embeddings

Backed by Postgres 17 + pgvector.

Core columns:
- Raw: `sender`, `sender_email`, `receiver`, `msg_date`, `subject`, `body`, `url_extracted`
- Flags: `urls` (0/1), `label` (0/1), derived `sender_domain`, `has_url`
- RAG vectors (1536 dims): `subject_emb`, `body_emb`, `url_emb`, `doc_emb`

See `db/init.sql` for full DDL, triggers, and HNSW indexes.

### Ingestion (DataPhish)

Use the loader to embed and insert the phishing-only corpus:

```bash
OPENAI_API_KEY="your-key" PYTHONPATH=api \
  python api/app/scripts/load_dataphish_corpus.py --split train --limit 8000
```

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

- Generate combined document embeddings (subject + body) -> `doc_emb`:

```bash
docker compose exec api python -m app.scripts.backfill_embeddings --target doc --batch-size 64 --model text-embedding-3-small
```

- Optionally generate other embeddings:

```bash
docker compose exec api python -m app.scripts.backfill_embeddings --target subject --batch-size 64
docker compose exec api python -m app.scripts.backfill_embeddings --target body --batch-size 64
docker compose exec api python -m app.scripts.backfill_embeddings --target url --batch-size 64
```

Verify counts:

```bash
docker compose exec db psql -U postgres -d app -c "SELECT COUNT(*) total, COUNT(doc_emb) doc, COUNT(subject_emb) subject, COUNT(body_emb) body, COUNT(url_emb) url FROM messages;"
```
