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
- `OPENAI_API_KEY` (required for `/ai/analyze`)
