from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import health, scan, ai

app = FastAPI(title="HackUMBC API", version="0.1.0")

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
