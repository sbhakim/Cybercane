# CyberCane API

FastAPI backend for CyberCane. Primary docs live in `README.md` and
`docs/OVERVIEW.md` at the repo root.

## Run (Conda)
```bash
conda run -n cybercane python -m uvicorn app.main:app --reload
```

## Environment
- `DATABASE_URL` (defaults to the Docker Compose DB if not set)
- `OPENAI_API_KEY` for `/ai/analyze`
