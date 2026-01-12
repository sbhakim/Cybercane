from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import health, scan, ai

# API metadata for OpenAPI documentation
description = """
## CyberCane Phishing Detection API

Privacy-preserving neuro-symbolic phishing detection system combining deterministic
security rules with retrieval-augmented generation (RAG).

### Key Features

* **Phase 1 (Deterministic):** DNS validation, authentication checks, URL analysis, content heuristics
* **Phase 2 (RAG):** PHI-redacted semantic analysis with nearest-neighbor retrieval and LLM reasoning
* **Privacy-First:** All PII redacted before external API calls (HIPAA-compatible architecture)
* **Explainable:** Multi-layered explanations with symbolic evidence, similarity scores, and tagged reasoning

### Performance

* **Precision:** 98.9% (RAG with k=8)
* **Recall:** 17.8% (conservative threshold optimized for low FPR)
* **FPR:** 0.16% (only 1 false alarm per 615 legitimate emails)
* **ROI:** 259.6× ($390K daily benefit for 10K email org)

### Quick Start

1. **Health Check:** `GET /health`
2. **Deterministic Scan:** `POST /scan` (Phase 1 only, no API key needed)
3. **Full Analysis:** `POST /ai/analyze` (Phase 1 + Phase 2, requires OPENAI_API_KEY)

### Documentation

* **Interactive API Docs:** [/docs](/docs) (Swagger UI)
* **Alternative Docs:** [/redoc](/redoc) (ReDoc)
* **GitHub:** https://github.com/pawelsloboda5/UMBC-hackathon
"""

app = FastAPI(
    title="CyberCane Phishing Detection API",
    description=description,
    version="0.2.0",
    contact={
        "name": "CyberCane Team",
        "url": "https://github.com/pawelsloboda5/UMBC-hackathon",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "health",
            "description": "Service health and database connectivity checks",
        },
        {
            "name": "scan",
            "description": "Phase 1 deterministic phishing detection (no AI, no API key required)",
        },
        {
            "name": "ai",
            "description": "Phase 2 RAG analysis with semantic similarity and LLM reasoning (requires OPENAI_API_KEY)",
        },
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(scan.router, prefix="/scan", tags=["scan"])
app.include_router(ai.router, prefix="/ai", tags=["ai"])
