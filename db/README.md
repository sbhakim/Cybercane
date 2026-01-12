# Hackathon Boilerplate DB

This directory contains the setup for the local Postgres database, including required extensions for the project.

## Quick Start (Recommended: Docker Compose)

1. **Ensure Docker and Docker Compose are installed.**
2. In the project root, run:

   ```sh
   docker-compose up --build db
   ```
   This will start a Postgres 17 database with the `postgis` and `vector` extensions pre-installed.

- The database will be available at `localhost:5432` by default.
- Default credentials (see `docker-compose.yml`):
  - User: `postgres`
  - Password: `postgres`
  - Database: `app`

## Manual Setup (Advanced)

1. **Install Postgres 17+ locally.**
2. Install the following extensions in your database:
   - `postgis`
   - `vector` (pgvector)
3. You can use the SQL in `init.sql` to initialize your database:
   ```sh
   psql -U postgres -d app -f init.sql
   ```
4. Make sure your API's `DATABASE_URL` points to your local database (see API README).

## Files
- `Dockerfile` – Builds a Postgres image with required extensions
- `init.sql` – Initializes the `vector` extension and creates Phase-1/Phase-2 tables

## Schema overview

- `messages` — one row per email. Includes:
  - Derived columns: `sender_domain` (from `sender_email`), `has_url` (from `urls`)
  - Phase-1 results: `verdict`, `score`, `reasons`, `indicators`, `redactions`, `redacted_body`
  - RAG prep: `subject_emb`, `body_emb`, `doc_emb` as `vector(1536)`, and `message_hash`
  - Timestamps: `created_at`, `updated_at` (maintained via trigger)
- `evidence` — auditable facts per message (rule hits, neighbors, PII matches, model reasons)
  - `message_id` has `ON DELETE CASCADE`

Constraints:
- `urls` and `label` are constrained to 0/1 via `CHECK`
- `verdict` constrained to `benign|needs_review|phishing`

Indexes:
- btree: `messages(sender_domain)`, `messages(msg_date)`, `messages(label)`
- GIN (optional): `messages(reasons)`, `messages(indicators)`
- HNSW (cosine): on `messages.body_emb` and `messages.subject_emb`, plus an optional partial HNSW on `label = 1`
  - Also on `messages.doc_emb` for combined subject+body retrieval (and optional partial index for `label = 1`)

### Enable pgvector

`init.sql` enables `vector`:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

### CSV ingest example

Use this to bulk-load rows (derived columns compute automatically):

```sql
COPY messages (sender, receiver, msg_date, subject, body, urls, label, sender_email)
FROM PROGRAM 'cat /tmp/phish.csv'
CSV HEADER;
```

### ANN search with HNSW (cosine)

You can tune recall/speed per session:

```sql
SET hnsw.ef_search = 100;  -- higher = better recall, slower
```

Example nearest-neighbor query on `body_emb` (using cosine distance via `vector_cosine_ops`):

```sql
WITH q AS (
  SELECT '[0.01, 0.02, 0.03, ... 0.00]'::vector AS vec  -- 1536 dims
)
SELECT m.id,
       1 - (m.body_emb <-> q.vec) AS cosine_similarity
FROM messages m, q
WHERE m.body_emb IS NOT NULL
ORDER BY m.body_emb <-> q.vec
LIMIT 10;
```

To prefer combined retrieval, query `doc_emb` similarly:

```sql
WITH q AS (
  SELECT $VEC$[0.01, 0.02, 0.03, ... 0.00]$VEC$::vector AS vec
)
SELECT m.id,
       1 - (m.doc_emb <-> q.vec) AS cosine_similarity
FROM messages m, q
WHERE m.doc_emb IS NOT NULL
ORDER BY m.doc_emb <-> q.vec
LIMIT 10;
```

Optional fast-path index limited to known phish exists and is used automatically when the query contains `WHERE label = 1`.

## Environment Variables
- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_PORT` can be set in your environment or `.env` file for Docker Compose overrides.

---

For more details, see the project root `readme_hackathon_boilerplate_next.md`.
