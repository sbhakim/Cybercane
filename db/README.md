# Database Layer (Postgres + pgvector)

This directory defines the research-grade database used by CyberCane. The schema
stores raw emails, deterministic outputs, and vector embeddings used for RAG
retrieval. It is optimized for reproducible experiments and offline analysis.

## Quick start (Docker Compose)

From the repo root:

```sh
docker compose up --build db
```

Default connection:
- Host: `localhost:5432`
- User: `postgres`
- Password: `postgres`
- Database: `app`

## Local setup (advanced)

1. Install PostgreSQL 17+.
2. Enable extensions:
   - `vector` (pgvector)
   - `postgis` (included for compatibility)
3. Initialize schema:
   ```sh
   psql -U postgres -d app -f init.sql
   ```
4. Set your API `DATABASE_URL` accordingly.

## Files

- `Dockerfile` - Postgres image with required extensions.
- `init.sql` - Creates extensions, tables, constraints, and indexes.

## Schema summary

- `messages` - one row per email:
  - Derived columns: `sender_domain` (from `sender_email`), `has_url` (from `urls`)
  - Phase 1 outputs: `verdict`, `score`, `reasons`, `indicators`, `redactions`, `redacted_body`
  - Embeddings: `subject_emb`, `body_emb`, `doc_emb` as `vector(1536)`, `message_hash`
  - Timestamps: `created_at`, `updated_at` (maintained by trigger)
- `evidence` - auditable facts per message (rule hits, neighbors, model reasons)
  - `message_id` enforces `ON DELETE CASCADE`

Constraints:
- `urls` and `label` constrained to 0/1 via `CHECK`
- `verdict` constrained to `benign|needs_review|phishing`

Indexes:
- B-tree: `messages(sender_domain)`, `messages(msg_date)`, `messages(label)`
- GIN (optional): `messages(reasons)`, `messages(indicators)`
- HNSW (cosine): `messages.subject_emb`, `messages.body_emb`, `messages.doc_emb`
  - Optional partial HNSW indexes on `label = 1` for phishing-only retrieval

## Data ingestion (CSV)

Use `COPY` for bulk load (derived columns compute automatically):

```sql
COPY messages (sender, receiver, msg_date, subject, body, urls, label, sender_email)
FROM PROGRAM 'cat /tmp/phish.csv'
CSV HEADER;
```

## Vector search

Tune recall/speed per session:

```sql
SET hnsw.ef_search = 100;
```

Nearest-neighbor query (cosine distance):

```sql
WITH q AS (
  SELECT '[0.01, 0.02, 0.03, ... 0.00]'::vector AS vec
)
SELECT m.id,
       1 - (m.doc_emb <-> q.vec) AS cosine_similarity
FROM messages m, q
WHERE m.doc_emb IS NOT NULL
ORDER BY m.doc_emb <-> q.vec
LIMIT 10;
```

## Configuration

Docker Compose honors:
- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_PORT`

## References

Project overview and experiment workflow:
- `README.md`
- `api/app/README.md`
