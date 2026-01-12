# CyberCane

CyberCane is a privacy-first phishing defense platform that combines deterministic
checks with AI + RAG to explain why an email is risky.

## Quick Start (Docker)
```bash
docker compose up --build
```
- Web: http://localhost:3000
- API: http://localhost:8000
- DB: localhost:5432 (user `postgres`, password `postgres`, db `app`)

## Local Dev (Conda + Node)
```bash
# Backend
conda run -n cybercane python -m uvicorn app.main:app --reload

# Frontend
cd web
npm install
npm run dev
```
Start Postgres with `docker compose up -d db` or set `DATABASE_URL` manually.

## Key Endpoints
- `GET /health`
- `POST /scan`
- `POST /ai/analyze`

## Docs
- `docs/OVERVIEW.md`

## Repo Layout
- `api/` FastAPI backend and pipeline logic
- `web/` Next.js frontend
- `db/` Postgres image and init SQL
- `datasets/` labeled phishing datasets and notes

## Environment
- `OPENAI_API_KEY` required for Phase 2 analysis
- `NEXT_PUBLIC_API_URL` and `INTERNAL_API_URL` for the web app
