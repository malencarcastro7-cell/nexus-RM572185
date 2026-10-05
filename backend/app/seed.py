# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Ambiente de demonstração: banco fictício "NexusBank" com 5 ativos e 6 relatórios reais de scanners.

Os relatórios são importados com datas retroativas (30 dias) para gerar histórico
de tendência e demonstrar a detecção automática de correções (MTTR).

Uso manual:  python -m app.seed --reset
"""

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine
from .models import Asset, AssetDependency, Finding, Occurrence, RiskSnapshot, ScanImport
from .parsers import parse_report
from .services.correlation import import_findings
from .services.pipeline import recalculate, take_snapshot

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

ASSETS = [
    {"name": "portal-clientes", "asset_type": "webapp", "internet_exposed": True, "business_criticality": 5,
     "data_classification": "confidential", "owner": "Squad Canais Digitais",
     "description": "Internet banking dos clientes pessoa física (extrato, busca, perfil)."},
    {"name": "api-pagamentos", "asset_type": "api", "internet_exposed": False, "business_criticality": 5,
     "data_classification": "confidential", "owner": "Squad Pagamentos",
     "description": "API de pagamentos e transferências (PIX e TED), chamada pelo portal."},
    {"name": "db-transacoes", "asset_type": "database", "internet_exposed": False, "business_criticality": 5,
     "data_classification": "restricted", "owner": "Time de Dados",
     "description": "PostgreSQL com transações financeiras e dados de cartão."},
    {"name": "servico-relatorios", "asset_type": "service", "internet_exposed": False, "business_criticality": 2,
     "data_classification": "internal", "owner": "Time de BI",
     "description": "Gera relatórios gerenciais internos a partir do banco de transações."},
    {"name": "intranet-rh", "asset_type": "webapp", "internet_exposed": False, "business_criticality": 3,
     "data_classification": "confidential", "owner": "TI Corporativa",
     "description": "Portal interno de recursos humanos."},
]

DEPENDENCIES = [
    ("portal-clientes", "api-pagamentos", "calls"),
    ("api-pagamentos", "db-transacoes", "reads/writes"),
    ("servico-relatorios", "db-transacoes", "reads"),
    ("intranet-rh", "servico-relatorios", "calls"),
]

# (dias atrás, arquivo, ativo)
IMPORTS = [
    (30, "sonarqube-portal-clientes.json", "portal-clientes"),
    (28, "zap-portal-clientes.json", "portal-clientes"),
    (21, "trivy-api-pagamentos-v2.3.0.json", "api-pagamentos"),
    (14, "snyk-api-pagamentos.json", "api-pagamentos"),
    (7, "trivy-servico-relatorios.json", "servico-relatorios"),
    (2, "trivy-api-pagamentos-v2.4.1.json", "api-pagamentos"),
]


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _backdate(db: Session, scan: ScanImport, when: datetime, snapshot: RiskSnapshot) -> None:
    scan.imported_at = when
    snapshot.taken_at = when
    for occ in db.scalars(select(Occurrence).where(Occurrence.scan_import_id == scan.id)):
        occ.seen_at = when
        f = occ.finding
        if f.first_seen is None or _aware(f.first_seen) > when:
            f.first_seen = when
        f.last_seen = when
    for f in db.scalars(select(Finding).where(Finding.asset_id == scan.asset_id, Finding.status == "resolved")):
        if f.resolved_at and _aware(f.resolved_at) > when:
            f.resolved_at = when


def reset(db: Session) -> None:
    for model in (Occurrence, Finding, ScanImport, RiskSnapshot, AssetDependency, Asset):
        db.execute(delete(model))
    db.commit()


def seed(db: Session) -> dict:
    assets = {}
    for data in ASSETS:
        a = Asset(**data)
        db.add(a)
        assets[a.name] = a
    db.flush()
    for src, dst, rel in DEPENDENCIES:
        db.add(AssetDependency(source_id=assets[src].id, target_id=assets[dst].id, relation=rel))
    db.flush()

    now = datetime.now(timezone.utc)
    for days, filename, asset_name in IMPORTS:
        report = json.loads((SAMPLES / filename).read_text(encoding="utf-8"))
        scanner, normalized = parse_report(report)
        scan = import_findings(db, assets[asset_name], scanner, filename, normalized)
        recalculate(db)
        snap = take_snapshot(db, f"Importação {scanner} em {asset_name}")
        _backdate(db, scan, now - timedelta(days=days), snap)
        db.flush()
    db.commit()
    return {"assets": len(assets), "imports": len(IMPORTS)}


def seed_if_empty() -> bool:
    with SessionLocal() as db:
        if db.scalar(select(Asset.id).limit(1)) is not None:
            return False
        seed(db)
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Carrega o ambiente de demonstração do NEXUS")
    parser.add_argument("--reset", action="store_true", help="apaga todos os dados antes de carregar")
    args = parser.parse_args()
    Base.metadata.create_all(engine)
    with SessionLocal() as session:
        if args.reset:
            reset(session)
        print(seed(session))
