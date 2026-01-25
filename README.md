# CyberCane
<!-- Note: Manuscript directory and LaTeX compilation content excluded from README (not uploaded to GitHub) -->

CyberCane is a privacy-first phishing detection system that combines deterministic rules, retrieval-augmented reasoning, and formal ontology inference to deliver transparent decisions in privacy-critical domains.

## Contributions
- **Neuro-symbolic pipeline:** Phase 1 symbolic checks followed by Phase 2 RAG-based semantic analysis with conservative escalation.
- **Privacy by design:** PII is redacted before any external API call; retrieval uses a phishing-only corpus.
- **Formal explanations:** PhishOnt maps observed indicators to attack types with verifiable reasoning chains.

## Results
Evaluations use Nazario.clean + SpamAssassin (test n=1,110) and DataPhish 2025 (test n=2,300; 60% LLM-generated).

Table 1: Detection performance (precision/recall/FPR)
| Dataset (test) | Method | Precision | Recall | FPR |
| --- | --- | --- | --- | --- |
| Nazario.clean + SpamAssassin | Phase 1 (rules) | 83.0% | 17.8% | 2.9% |
| Nazario.clean + SpamAssassin | Phase 2 (RAG, k=8) | 98.9% | 17.8% | 0.16% |
| DataPhish 2025 | Phase 1 (rules) | 93.4% | 20.5% | — |
| DataPhish 2025 | Phase 2 (RAG, k=8) | 98.2% | 99.1% | — |

`—` = not reported in manuscript for DataPhish FPR.

Table 2: Privacy and cost tradeoffs vs direct LLM baseline
| Method | Precision | Recall | F1 | FPR | Cost/email | PHI exposure |
| --- | --- | --- | --- | --- | --- | --- |
| CyberCane (RAG, redacted) | 98.9% | 17.8% | 30.1% | 0.16% | $0.0017 | 0% |
| GPT-4 Direct (gpt-4.1-mini, unredacted) | 93.2% | 99.0% | 96.0% | 5.9% | $0.0001 | 53.2% |

Table 3: PhishOnt coverage on the test split
| Split | Coverage |
| --- | --- |
| Overall (n=1,110) | 85.2% |
| Phishing (n=495) | 77.4% |
| Benign (n=615) | 91.5% |

Healthcare case study estimates 259.6x ROI for a 10K-email/day organization.

## System overview
- **Phase 1 (Deterministic):** DNS validation (MX/SPF/DMARC) + URL heuristics + urgency/credential cues.
- **Phase 2 (RAG):** PII redaction -> embeddings (text-embedding-3-small) -> HNSW retrieval (k=8) -> GPT-4.1-mini explanations -> conservative verdict thresholds.

## Research lineage
This repository extends the work initiated at https://github.com/pawelsloboda5/UMBC-hackathon, evolving the hackathon prototype into a research-grade neuro-symbolic pipeline with privacy safeguards and reproducible evaluation tooling.

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

**API endpoints:** `GET /health` | `POST /scan` | `POST /ai/analyze`
**Environment:** Python 3.11, PostgreSQL 17+pgvector, Node 18+, OpenAI API (text-embedding-3-small, GPT-4.1-mini)
**Required env vars:** `OPENAI_API_KEY`, `DATABASE_URL`

## Reproducing results
Use the evaluation scripts in `reports/` to regenerate tabular metrics (no plots or curves). Public datasets (Nazario.clean, SpamAssassin) must be placed in `datasets/`.

## Repository layout
- `api/` — FastAPI backend and pipeline logic
- `web/` — Next.js frontend
- `db/` — Postgres image and initialization SQL
- `datasets/` — Data splits and corpus files (not all are tracked)
- `reports/` — Evaluation scripts and generated artifacts

## Citation
If you use CyberCane in your research, please cite:

```bibtex
@inproceedings{cybercane2025,
  title={CyberCane: Neuro-Symbolic RAG for Privacy-Preserving Phishing Detection with Formal Ontology Reasoning},
  author={[Authors]},
  booktitle={[Conference/Journal]},
  year={2025}
}
```

For questions or collaboration inquiries, please open an issue or email safayat dot b dot hakim at gmail dot com.
