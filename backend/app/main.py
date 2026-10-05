# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Ponto de entrada da API NEXUS (FastAPI).

Documentação interativa: http://localhost:8000/docs
"""

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from . import __version__
from .config import settings
from .database import Base, engine, get_db
from .routers import assets, dashboard, findings, imports
from .seed import reset, seed, seed_if_empty
from .services.ai import provider_info

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("nexus")


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)
    if settings.seed_demo and seed_if_empty():
        log.info("Ambiente de demonstração carregado (NexusBank).")
    log.info("IA ativa: %s", provider_info())
    yield


app = FastAPI(
    title="NEXUS ASPM",
    version=__version__,
    description="Application Security Posture Management orientado por IA: ingestão, correlação, "
    "attack path analysis e priorização contextual de vulnerabilidades.",
    license_info={"name": "BSD-3-Clause", "url": "https://opensource.org/license/bsd-3-clause"},
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

for r in (dashboard.router, assets.router, imports.router, findings.router):
    app.include_router(r)


@app.get("/api/health", tags=["sistema"])
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok", "version": __version__, "database": engine.dialect.name, "ai": provider_info()}


@app.post("/api/demo/reset", tags=["sistema"])
def demo_reset(db: Session = Depends(get_db)):
    """Apaga todos os dados e recarrega o ambiente de demonstração."""
    reset(db)
    return seed(db)
