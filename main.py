"""
LLM Agent Security Lab — Prompt Injection Scanner
Zero-trust input scanner with rule-based + heuristic detection.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from api.routes import router
from api.logger import setup_logger, log_startup

logger = setup_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log_startup()
    yield
    logger.info("🛑 Scanner shutting down")


app = FastAPI(
    title="LLM Prompt Injection Scanner",
    description=(
        "Zero-trust prompt injection scanner. "
        "Rule-based + heuristic detection with composite risk scoring. "
        "Supports multi-language, leetspeak normalisation, and encoding-based evasion detection."
    ),
    version="2.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)