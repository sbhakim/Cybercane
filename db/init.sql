-- Enable required extension(s)
CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================================
-- Phase-1 (deterministic) classifier schema + Phase-2 RAG prep
-- ============================================================================

-- messages: one row per email
CREATE TABLE IF NOT EXISTS messages (
  id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

  -- Raw and normalized sender fields
  sender            TEXT,                    -- display name or header value if present
  sender_email      TEXT NOT NULL,           -- mailbox address from CSV
  sender_domain     TEXT GENERATED ALWAYS AS (lower(split_part(sender_email, '@', 2))) STORED,

  receiver          TEXT,
  msg_date          TIMESTAMPTZ,             -- parsed from CSV date
  subject           TEXT,
  body              TEXT,
  url_extracted     TEXT,

  -- Dataset semantics
  urls              SMALLINT NOT NULL CHECK (urls IN (0, 1)),
  has_url           BOOLEAN GENERATED ALWAYS AS (urls = 1) STORED,
  label             SMALLINT NULL CHECK (label IN (0, 1)),  -- 0 legit, 1 phishing

  -- Phase-1 results
  verdict           TEXT NULL CHECK (verdict IN ('benign','needs_review','phishing')),
  score             INT NULL,
  reasons           JSONB NOT NULL DEFAULT '{}'::jsonb,     -- array or map, caller's choice
  indicators        JSONB NOT NULL DEFAULT '{}'::jsonb,     -- DNS/auth/url/urgency hits
  redactions        JSONB NOT NULL DEFAULT '{}'::jsonb,     -- counts per PII type
  redacted_body     TEXT,

  -- RAG prep
  subject_emb       VECTOR(1536),
  body_emb          VECTOR(1536),
  url_emb           VECTOR(1536),
  doc_emb           VECTOR(1536),
  message_hash      TEXT UNIQUE,                             -- e.g., SHA256 of normalized sender/subject/body

  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- evidence: audit/explainability records
CREATE TABLE IF NOT EXISTS evidence (
  id          BIGSERIAL PRIMARY KEY,
  message_id  BIGINT REFERENCES messages(id) ON DELETE CASCADE,
  kind        TEXT CHECK (kind IN ('rule_hit','retrieval_neighbor','pii_match','model_reason')),
  ref_id      BIGINT NULL,                  -- neighbor message id or rule id (if applicable)
  score       NUMERIC(6,4) NULL,            -- distance/weight
  details     JSONB NOT NULL DEFAULT '{}'::jsonb,  -- structured facts (domains, links, etc.)
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Maintain updated_at automatically
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.proname = 'set_updated_at' AND n.nspname = 'public'
  ) THEN
    CREATE FUNCTION public.set_updated_at() RETURNS trigger AS $fn$
    BEGIN
      NEW.updated_at := now();
      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql;
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_messages_set_updated_at'
  ) THEN
    CREATE TRIGGER trg_messages_set_updated_at
    BEFORE UPDATE ON messages
    FOR EACH ROW
    EXECUTE FUNCTION public.set_updated_at();
  END IF;
END$$;

-- --------------------------------------------------------------------------
-- Indexing
-- --------------------------------------------------------------------------

-- btree indexes for common lookups
CREATE INDEX IF NOT EXISTS idx_messages_sender_domain ON messages (sender_domain);
CREATE INDEX IF NOT EXISTS idx_messages_msg_date ON messages (msg_date);
CREATE INDEX IF NOT EXISTS idx_messages_label ON messages (label);

-- Optional: GIN indexes for dashboard filtering on JSONB fields
CREATE INDEX IF NOT EXISTS idx_messages_reasons_gin ON messages USING gin (reasons);
CREATE INDEX IF NOT EXISTS idx_messages_indicators_gin ON messages USING gin (indicators);

-- HNSW indexes for cosine distance (pgvector)
CREATE INDEX IF NOT EXISTS idx_messages_body_emb_hnsw
  ON messages USING hnsw (body_emb vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS idx_messages_subject_emb_hnsw
  ON messages USING hnsw (subject_emb vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS idx_messages_url_emb_hnsw
  ON messages USING hnsw (url_emb vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

-- Optional fast path for known phish retrieval (partial HNSW on label=1)
CREATE INDEX IF NOT EXISTS idx_messages_body_emb_hnsw_phish
  ON messages USING hnsw (body_emb vector_cosine_ops)
  WITH (m = 16, ef_construction = 64)
  WHERE label = 1;

-- Combined doc embedding (subject + body) HNSW
CREATE INDEX IF NOT EXISTS idx_messages_doc_emb_hnsw
  ON messages USING hnsw (doc_emb vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);

-- Optional partial HNSW on doc_emb for known phish
CREATE INDEX IF NOT EXISTS idx_messages_doc_emb_hnsw_phish
  ON messages USING hnsw (doc_emb vector_cosine_ops)
  WITH (m = 16, ef_construction = 64)
  WHERE label = 1;

-- Helpful FK lookup
CREATE INDEX IF NOT EXISTS idx_evidence_message_id ON evidence (message_id);

-- Example: tune search recall/speed at query time
-- SET hnsw.ef_search = 100;

-- Example: bulk CSV ingest (adjust path as needed)
-- COPY messages (sender, receiver, msg_date, subject, body, urls, label, sender_email)
-- FROM PROGRAM 'cat /tmp/phish.csv'
-- CSV HEADER;
