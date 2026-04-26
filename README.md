# CyberCane: Neuro-Symbolic RAG for Privacy-Preserving Phishing Detection

> **99.5% precision · 0.16% FPR · 542× optimistic ROI · 0% PHI exposure**

CyberCane is a privacy-first phishing detection framework that combines deterministic symbolic rules, retrieval-augmented generation (RAG), and formal OWL ontology reasoning to deliver transparent, auditable decisions in privacy-critical domains such as healthcare and finance.

Research paper — preprint available upon request.

---

## Architecture

<p align="center">
  <img src="dataset_cybercane/cybercane_architecture.jpg" alt="CyberCane Architecture" width="820"/>
</p>

**Phase 1 — Deterministic Symbolic Analysis:** Lightweight DNS/MX/SPF/DMARC checks, URL heuristics, urgency and credential cues produce risk scores with instant verifiable explanations.

**Phase 2 — Privacy-Preserving RAG:** PII is redacted via `pii.py` before any external API call. Redacted content is embedded (text-embedding-3-small, 1536-d), retrieved against a phishing-only HNSW corpus (k=8), and classified by GPT-4.1-mini conditioned on Phase 1 indicators and PhishOnt ontology context.

**PhishOnt — OWL Ontology:** Maps symbolic indicators to 8 attack types (CredentialTheft, PrescriptionFraud, etc.) via description-logic axioms, generating verifiable reasoning chains for audit trails.

---

## Key Results

### Detection performance

| Dataset (test) | Method | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Nazario + SpamAssassin (n=1,110) | Phase 1 (rules, threshold=2) | 83.0% | 17.8% | 0.293 | 2.9% |
| Nazario + SpamAssassin (n=1,110) | **Phase 2 RAG (k=8)** | **99.5%** | **37.2%** | **0.541** | **0.16%** |
| DataPhish 2025 (n=2,337) | Phase 1 (rules) | 93.4% | 20.5% | 0.336 | — |
| DataPhish 2025 (n=2,337) | **Phase 2 RAG (k=8)** | **98.2%** | **99.1%** | **0.987** | — |

Phase 2 RAG delivers a **78.6-point recall gain over Phase 1** within the CyberCane pipeline on AI-generated threats (DataPhish 2025). On Nazario/SpamAssassin the 37.2% recall reflects a deliberate FPR-first threshold; Aggressive mode recovers 44.6% recall while maintaining 99.5% precision and 0.16% FPR.

### Privacy-constrained baseline comparison

| Method | Precision | Recall | F1 | FPR | Cost/Email | PHI Exposure |
|---|---|---|---|---|---|---|
| **CyberCane RAG (k=8)** | **99.5%** | 37.2% | 0.541 | **0.16%** | $0.0017 | **0%** |
| TF-IDF LR + Redaction (same `pii.py`) | 98.8% | 97.4% | 0.981 | 0.98% | $0 | **0%** |
| TF-IDF LR (no redaction) | 98.6% | 97.4% | 0.980 | 1.14% | $0 | ~53% |
| GPT-4 Direct (gpt-4o-mini, unredacted) | 93.2% | 99.0% | 0.960 | 5.9% | $0.0001 | 53.2% |

CyberCane's value over the privacy-constrained TF-IDF baseline is **6× lower FPR** (0.16% vs 0.98%), PhishOnt verifiable reasoning chains, and tunable operating points — none available in TF-IDF.

### Robustness across 18 creator sources (DataPhish 2025, n=2,300)

| Group | N | Precision | Recall | F1 |
|---|---|---|---|---|
| Human-written | 559 | 97.5% | 99.5% | 98.5% |
| LLM-generated (17 models) | 1,741 | 98.4% | 99.1% | 98.7% |
| DeepSeek-Chat | 602 | 99.1% | 99.1% | 99.1% |
| OpenAI GPT family | 596 | 97.1% | 99.3% | 98.2% |
| Amazon Nova / Grok / Codestral | 156 | 100.0% | 100.0% | 100.0% |
| **Overall Phase 2 RAG** | **2,300** | **98.1%** | **99.2%** | **98.7%** |

F1 range across all 18 creator sources: **0.976–1.000**. Detection is statistically indistinguishable between human-written and LLM-generated phishing.

### Operating point flexibility

| Mode | Precision | Recall | F1 | FPR | Use Case |
|---|---|---|---|---|---|
| Conservative | 99.3% | 29.5% | 0.455 | 0.16% | High-stakes clinical |
| Baseline (pipeline default) | 99.5% | 37.2% | 0.541 | 0.16% | Current deployment |
| Balanced | 99.5% | 40.0% | 0.571 | 0.16% | General healthcare |
| Moderate | 99.5% | 42.2% | 0.593 | 0.16% | High-volume screening |
| Aggressive | 99.5% | 44.6% | 0.616 | 0.16% | Maximum coverage |

All five modes share the same 0.16% FPR via the Phase 1 high-confidence threshold.

---

## Notable Findings

**Layered defense against rule evasion.** Of the 1,589 phishing emails in the DataPhish 2025 test set, 79.5% (n=1,264) score zero in Phase 1 — attacks with valid DNS infrastructure and no urgency cues that entirely bypass symbolic rules. Phase 2 RAG correctly classifies **99.0% of these Phase 1-evaded emails**, leaving a combined two-phase miss rate of only **0.8%**. This demonstrates the intended architectural property: the symbolic layer handles flagrant violations instantly; the neural layer provides semantic recovery for attacks that deliberately avoid rule triggers.

**Active PII redaction.** Across 2,337 DataPhish 2025 test emails, **50.7% contained at least one redacted PII field** (mean 1.63 items/email). LLM-generated emails averaged 1.73 items/email versus 1.30 for human-written — yet detection F1 remained 0.987 for both groups, confirming that semantic classification is preserved under active masking.

**PhishOnt confidence discriminability.** Despite similar binary activation rates across classes, phishing activations carry a mean ontology confidence of 54.6% versus 52.8% for benign (+1.84pp). 85.5% of benign activations fall *below* the typical phishing confidence level, confirming PhishOnt is discriminative at the confidence level even when binary activation rates appear similar.

**Healthcare ROI.** At 37.2% recall and 10,000 emails/day, the system detects ~164 phishing attacks daily ($1,506/day operational cost), yielding a **542× optimistic ROI**. At DataPhish 2025 recall (99.1%), optimistic and conservative ROI converge to 1,450× and 1,437× respectively.

---

## System Overview

```
Email Input
    │
    ▼
Phase 1: Deterministic Symbolic Analysis
  ├─ DNS/MX/SPF/DMARC checks
  ├─ URL obfuscation patterns
  ├─ Urgency & credential cues
  └─ PhishOnt OWL inference → attack type + reasoning chain
    │
    ▼ (if score < threshold → escalate to Phase 2)
    │
[PII Redaction — pii.py — before any external call]
    │
    ▼
Phase 2: Neural RAG Classification
  ├─ text-embedding-3-small (1536-d) embedding
  ├─ HNSW vector search — phishing-only corpus (k=8)
  ├─ GPT-4.1-mini conditioned on: redacted email + Phase 1 indicators
  │   + PhishOnt attack types + retrieved examples
  └─ Similarity-driven verdict (top_sim ≥ 0.40, avg_top3 ≥ 0.35)
    │
    ▼
Final verdict + confidence score + tagged explanation
```

**Stack:** FastAPI (Python 3.11) · PostgreSQL 17 + pgvector · Next.js 15 · OpenAI API (text-embedding-3-small, gpt-4.1-mini)

---

## Quick Start

**Docker (recommended — 5 minutes)**
```bash
git clone https://github.com/sbhakim/Cybercane.git && cd Cybercane
cp .env.example .env          # add OPENAI_API_KEY
docker compose up --build
# Web UI: http://localhost:3000 | API docs: http://localhost:8000/docs
```

**Local development**
```bash
conda env create -f environment.yml && conda activate cybercane
export OPENAI_API_KEY="sk-..."
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/app"
docker compose up -d db
cd api && python -m uvicorn app.main:app --reload   # Terminal 1
cd web && npm install && npm run dev                # Terminal 2
```

**API endpoints**
```bash
# Phase 1 only — no API key required
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"sender":"alert@suspicious.com","subject":"Urgent: verify account","body":"Click http://bit.ly/abc","url":1}'

# Phase 1 + Phase 2 RAG — requires OPENAI_API_KEY
curl -X POST http://localhost:8000/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{"sender":"alert@suspicious.com","subject":"Urgent: verify account","body":"Click http://bit.ly/abc","url":1}'
```

| Endpoint | Description |
|---|---|
| `GET /health` | Service liveness check |
| `POST /scan` | Phase 1 symbolic analysis only |
| `POST /ai/analyze` | Full dual-phase pipeline with explanation |

---

## Reproducing Results

Evaluation scripts in `reports_cybercane/` reproduce all main-paper tables without external dependencies beyond the public datasets.

```bash
cd reports_cybercane/

# Bootstrap confidence intervals (Table 19)
python bootstrap_ci.py

# McNemar χ² significance tests (Phase 1 vs Phase 2)
python statistical_significance.py

# F1-maximizing threshold grid search
python tune_thresholds.py

# Daily operational cost-benefit analysis (Table 7)
python cost_benefit_analysis.py

# Deterministic pipeline evaluator on test split
python eval_test_split.py

# TF-IDF + redacted baseline comparison (Table 4)
# Run from api/ with conda cybercane env:
python -m app.evaluation.baselines

# PhishOnt confidence discriminability (Section 5.2)
python -m app.evaluation.ontology_coverage
```

Public datasets required in `datasets/`: `Nazario.clean.csv`, `SpamAssassin.csv`.  
DataPhish 2025 splits (`dataphish_train.jsonl`, `dataphish_test.jsonl`) are included in `dataset_cybercane/`.

---

## Repository Layout

```
Cybercane/
├── api/                        # FastAPI backend
│   └── app/
│       ├── pipeline/
│       │   ├── pii.py          # PII redaction (email, phone, SSN, CC, DOB)
│       │   ├── rag.py          # Phase 2 RAG pipeline
│       │   └── symbolic.py     # Phase 1 rule engine
│       ├── evaluation/
│       │   ├── baselines.py    # TF-IDF + redacted baseline comparison
│       │   └── ontology_coverage.py  # PhishOnt coverage + confidence analysis
│       └── ontology/           # PhishOnt OWL files
├── web/                        # Next.js frontend
├── db/                         # PostgreSQL + pgvector initialization
├── dataset_cybercane/          # Tracked reproducibility artifacts
│   ├── dataphish_train.jsonl   # DataPhish 2025 train split
│   ├── dataphish_test.jsonl    # DataPhish 2025 test split (n=2,337)
│   ├── Nazario.clean.csv       # Cleaned Nazario phishing corpus
│   └── cybercane_architecture.jpg
├── reports_cybercane/          # Standalone evaluation scripts
│   ├── bootstrap_ci.py
│   ├── cost_benefit_analysis.py
│   ├── statistical_significance.py
│   ├── tune_thresholds.py
│   └── eval_test_split.py
└── environment.yml             # Conda environment (Python 3.11)
```

---

## Research Lineage

This repository extends the prototype at [UMBC Hackathon](https://github.com/pawelsloboda5/UMBC-hackathon) into a full neuro-symbolic research pipeline with formal ontology reasoning, privacy-by-design architecture, and research-grade evaluation workflows.

---

## Citation

```bibtex
@article{hakim2026cybercane,
  title  = {CyberCane: Neuro-Symbolic RAG for Privacy-Preserving Phishing Detection
            with Formal Ontology Reasoning},
  author = {Hakim, Safayat Bin and Afzal, Aniqa and Zhao, Qi and
            Majmundar, Vigna and Sloboda, Pawel and Song, Houbing Herbert},
  year   = {2026}
}
```

---

For questions or collaboration, open an issue or reach out via email — address: `safayat [dot] b [dot] hakim [at] gmail [dot] com`
