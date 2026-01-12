# CyberCane
<!-- Note: Manuscript directory and LaTeX compilation content excluded from README (not uploaded to GitHub) -->

CyberCane is a privacy-first phishing defense system that combines deterministic security rules with retrieval-augmented reasoning to produce explainable risk assessments. The project targets healthcare workflows where low false-positive rates and transparent decision logic are essential.

## Research lineage
This repository is an academic extension of the work initiated at https://github.com/pawelsloboda5/UMBC-hackathon. The current codebase expands the original architecture with a clearer neuro-symbolic pipeline, stronger privacy controls, and a more rigorous evaluation workflow suitable for research use.

## Primary contributions
- **Neuro-symbolic pipeline:** Phase 1 uses deterministic checks (authentication presence, URL heuristics, urgency cues, credential requests) to produce an explainable baseline decision; Phase 2 uses retrieval-augmented reasoning to provide semantic context and calibrated escalation.
- **Privacy by design:** Sensitive identifiers are redacted before any external model call; retrieval operates over a curated phishing-only corpus to ground explanations.
- **Reproducible evaluation:** A public, mixed-label evaluation pipeline supports train/val/test splits, deterministic metrics, and AI summary statistics with consistent scripts and generated artifacts.

## Performance summary
Evaluated on mixed-label test split (n=1,110) from Nazario.clean + SpamAssassin public datasets.

| Metric | Phase 1 (Rules) | Phase 2 (RAG) | Improvement |
| --- | --- | --- | --- |
| Precision | 83.0% | **98.9%** | +15.9pp |
| Recall | 17.8% | 17.8% | — |
| FPR | 2.9% | **0.16%** | **91% reduction** |
| AUROC | 0.574 | 0.574 | — |
| Latency | 12ms | 487ms | +475ms |
| Cost/email | $0 | $0.002 | — |

**ROI for 10K email organization:** 259.6× ($390K daily benefit vs. $1.5K cost)

The conservative recall (17.8%) reflects a precision-first design choice where false alarms carry high operational costs in healthcare settings. RAG achieves 91% FPR reduction while maintaining recall.

## System architecture
**Phase 1 (Deterministic):** DNS validation (MX/SPF/DMARC) → URL analysis (shorteners, IP literals) → Content heuristics (urgency, credential requests)

**Phase 2 (RAG):** PII redaction → Embedding (text-embedding-3-small) → HNSW retrieval (k=8, phishing-only corpus) → LLM reasoning (GPT-4.1-mini) → Conservative verdict escalation

**Key innovations:** (1) Privacy-by-design with PII redaction before external API calls, (2) Phishing-only retrieval corpus prevents benign contamination, (3) Multi-tagged explanations ([URL], [AUTH], [SIMILARITY], [CONTENT], [URGENCY]), (4) Conservative thresholds (0.70/0.55) calibrated for low FPR.

## Explainability analysis
- **Tag distribution:** [URL] 28%, [AUTH] 24%, [SIMILARITY] 22%, [CONTENT] 16%, [URGENCY] 10%
- **Multi-evidence verdicts:** 73% include 2+ tag types
- **Explanation conciseness:** 11.6 words/reason average
- **Verdict distribution:** 86.0% benign, 9.5% needs_review, 4.4% phishing

## Quick start (5 minutes)

**Docker deployment (recommended)**
```bash
docker compose up --build
# Web: http://localhost:3000 | API: http://localhost:8000 | Docs: http://localhost:8000/docs
```

**Local development**
```bash
conda env create -f environment.yml && conda activate cybercane
export OPENAI_API_KEY="your-key" DATABASE_URL="postgresql://postgres:postgres@localhost:5432/app"
docker compose up -d db
cd api && python -m uvicorn app.main:app --reload  # Terminal 1
cd web && npm install && npm run dev               # Terminal 2
```

**Try the API** (interactive docs at http://localhost:8000/docs)
```bash
# Phase 1: Rules-based scan (no API key)
curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" \
  -d '{"sender":"alert@bank.com","subject":"Urgent: verify account","body":"Click: http://bit.ly/x","url":1}'

# Phase 2: Full RAG analysis (requires OPENAI_API_KEY)
curl -X POST http://localhost:8000/ai/analyze -H "Content-Type: application/json" \
  -d '{"sender":"alert@bank.com","subject":"Urgent: verify account","body":"Click: http://bit.ly/x","url":1}'
```

**API endpoints:** `GET /health` (status) | `POST /scan` (Phase 1) | `POST /ai/analyze` (Phase 2)
**Environment:** Python 3.11, PostgreSQL 17+pgvector, Node 18+, OpenAI API (text-embedding-3-small, GPT-4.1-mini)
**Required env vars:** `OPENAI_API_KEY`, `DATABASE_URL`

## Reproducing results
```bash
conda activate cybercane
PYTHONPATH=api python reports/generate_full_curves.py          # ROC/PR curves
PYTHONPATH=api python reports/rag_ablations.py --tuned         # RAG k-neighbor ablation
PYTHONPATH=api python reports/bootstrap_ci.py --n-bootstrap 10000  # Confidence intervals
PYTHONPATH=api python reports/evaluate_explanations.py         # Explanation quality
PYTHONPATH=api python reports/cost_benefit_analysis.py         # ROI calculation
```
Scripts generate CSV tables and PDF figures. Public datasets (Nazario.clean, SpamAssassin) must be placed in `datasets/` directory.

## Repository layout
- `api/` — FastAPI backend and pipeline logic
- `web/` — Next.js frontend
- `db/` — Postgres image and initialization SQL
- `reports/` — Evaluation scripts generating CSV tables and PDF figures

## Citation

If you use CyberCane in your research, please cite:

```bibtex
@inproceedings{cybercane2025,
  title={CyberCane: Privacy-Preserving Neuro-Symbolic Phishing Defense for Healthcare},
  author={[Authors]},
  booktitle={[Conference/Journal]},
  year={2025}
}
```

For questions or collaboration inquiries, please open an issue on GitHub.
