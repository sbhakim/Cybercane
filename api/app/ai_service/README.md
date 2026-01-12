Simple AI analysis service for Phase‑2 RAG.

Responsibilities:
- Embed input email (subject + body) with `text-embedding-3-small` (1536 dims)
- Retrieve nearest neighbors on `messages.doc_emb` via pgvector cosine
- Summarize short explanations using OpenAI Responses API
- Produce an AI verdict combining Phase‑1 output and neighbor similarity

Environment:
- Requires `OPENAI_API_KEY` inside the api container

Endpoints:
- `POST /ai/analyze` — runs Phase‑1 first (redaction + deterministic), then AI analysis


