# CyberCane API

Research backend for the CyberCane neuro-symbolic phishing system. This
service exposes Phase 1 deterministic scanning and Phase 2 RAG analysis
used in evaluation pipelines and experiments.

Primary documentation:
- `README.md`
- `docs/OVERVIEW.md`

## Run (Conda)

```bash
conda run -n cybercane python -m uvicorn app.main:app --reload
```

## Environment

- `DATABASE_URL` (defaults to the Docker Compose DB if not set)
- `OPENAI_API_KEY` (used for embeddings + LLM; required unless DeepSeek is configured)
- `OPENAI_BASE_URL` (optional custom OpenAI-compatible endpoint)
- `DEEPSEEK_API_KEY` (optional fallback provider for embeddings + LLM)
- `DEEPSEEK_BASE_URL` (optional; defaults to `https://api.deepseek.com`)
- `DEEPSEEK_MODEL` (DeepSeek chat model name if using DeepSeek)
- `DEEPSEEK_EMBEDDING_MODEL` (required for DeepSeek embeddings)
- `THRESHOLD_CONFIG_PATH` (optional JSON thresholds for RAG verdicts)

## Endpoints

- `GET /health` (service + DB status)
- `POST /scan` (Phase 1 deterministic scan)
- `POST /ai/analyze` (Phase 1 + Phase 2 RAG; GPT-4.1-mini by default with DeepSeek fallback)
