# CyberCane

CyberCane is a privacy-first phishing defense system that combines deterministic security rules with retrieval-augmented reasoning to produce explainable risk assessments. The project targets healthcare workflows where low false-positive rates and transparent decision logic are essential.

## Research lineage
This repository is an academic extension of the work initiated at https://github.com/pawelsloboda5/UMBC-hackathon. The current codebase expands the original architecture with a clearer neuro-symbolic pipeline, stronger privacy controls, and a more rigorous evaluation workflow suitable for research use.

## Primary contributions
- **Neuro-symbolic pipeline:** Phase 1 uses deterministic checks (authentication presence, URL heuristics, urgency cues, credential requests) to produce an explainable baseline decision; Phase 2 uses retrieval-augmented reasoning to provide semantic context and calibrated escalation.
- **Privacy by design:** Sensitive identifiers are redacted before any external model call; retrieval operates over a curated phishing-only corpus to ground explanations.
- **Reproducible evaluation:** A public, mixed-label evaluation pipeline supports train/val/test splits, deterministic metrics, and AI summary statistics with consistent scripts and generated artifacts.

## System architecture (summary)
**Phase 1: Deterministic analysis**
- DNS-authentication presence checks (MX/SPF/DMARC).
- URL host extraction, shortener detection, IP literal detection.
- Content cues for urgency and credential/PII requests.

**Phase 2: RAG analysis**
- Redact PII in subject/body.
- Embed redacted content with OpenAI embeddings (text-embedding-3-small).
- Retrieve nearest phishing examples via pgvector HNSW.
- Generate concise reasons with an LLM (GPT-4.1-mini); similarity-driven score and verdict remain conservative.

## Data and evaluation
The evaluation pipeline uses public datasets (Nazario.clean and SpamAssassin). These datasets are not included in this repository by default. Place datasets under `datasets/` when running experiments locally.

Typical evaluation workflow:
1) Build combined dataset and train/val/test splits.
2) Load train split into Postgres and backfill embeddings.
3) Run threshold tuning and test split evaluation.
4) Export tables for manuscript use.

## Quick start (Docker)
```bash
docker compose up --build
```
- Web: http://localhost:3000  
- API: http://localhost:8000  
- DB: localhost:5432 (user `postgres`, password `postgres`, db `app`)

## Local development (Conda + Node)
```bash
# Backend
conda run -n cybercane python -m uvicorn app.main:app --reload

# Frontend
cd web
npm install
npm run dev
```
Start Postgres with `docker compose up -d db` or set `DATABASE_URL` manually.

## Key API endpoints
- `GET /health` — service + DB status
- `POST /scan` — deterministic scan only (Phase 1)
- `POST /ai/analyze` — deterministic scan + RAG analysis (Phase 1 + Phase 2)

Minimal request schema:
```json
{
  "sender": "alert@bank-example.com",
  "receiver": "user@example.com",
  "subject": "Urgent: verify your account",
  "body": "Please verify your account at https://example.com/login",
  "url": 1
}
```

## Reproducibility notes
- **Environment:** Python 3.11, PostgreSQL 17 + pgvector, Node 18+ (Node 20 recommended for local builds).
- **Embedding model:** `text-embedding-3-small` (1536 dims).
- **LLM:** `gpt-4.1-mini` for concise, tagged explanations.

## Environment variables
- `OPENAI_API_KEY` required for Phase 2 analysis.
- `DATABASE_URL` for API database connectivity.
- `NEXT_PUBLIC_API_URL` and `INTERNAL_API_URL` for the web app.

## Limitations and scope
- Healthcare-specific datasets are not distributed with this repo.
- Retrieval is phishing-only, which biases similarity-based escalation toward caution.
- DNS checks are conservative and may undercount legitimate domain configurations.

## Repository layout
- `api/` FastAPI backend and pipeline logic
- `web/` Next.js frontend
- `db/` Postgres image and initialization SQL

## Citation
If you use this project in research, cite the CyberCane paper or acknowledge the source repository.
