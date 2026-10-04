-- provenance columns for an auditable retrieval corpus.
-- Rows store sanitized text only (subject, body, redacted_body hold boundary output).

ALTER TABLE messages ADD COLUMN IF NOT EXISTS row_uid          TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS split            TEXT CHECK (split IN ('train', 'val', 'test'));
ALTER TABLE messages ADD COLUMN IF NOT EXISTS split_seed       INT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS source           TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS fine_class       TEXT CHECK (fine_class IN ('phishing', 'spam', 'legit'));
ALTER TABLE messages ADD COLUMN IF NOT EXISTS dedup_group      TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS redactor_version TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS embed_model      TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_row_uid_seed ON messages (row_uid, split_seed);
CREATE INDEX IF NOT EXISTS idx_messages_split ON messages (split, fine_class);

-- Partial cosine HNSW over training phishing, matching the retrieval filter.
CREATE INDEX IF NOT EXISTS idx_messages_doc_emb_hnsw_train_phish
  ON messages USING hnsw (doc_emb vector_cosine_ops)
  WITH (m = 16, ef_construction = 64)
  WHERE split = 'train' AND fine_class = 'phishing';
