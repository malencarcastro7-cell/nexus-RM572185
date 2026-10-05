# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Modelo de dados do NEXUS.

- Asset: aplicação/serviço/banco com contexto de negócio (exposição, criticidade).
- AssetDependency: aresta do grafo (origem acessa/depende do destino).
- Finding: vulnerabilidade única e consolidada (após deduplicação).
- Occurrence: cada aparição bruta de uma vulnerabilidade em um relatório de scanner.
- ScanImport: registro de cada relatório importado.
- RiskSnapshot: histórico da postura de risco para tendência.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    """Serializa datas sempre em UTC (o SQLite devolve datas sem fuso)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    asset_type: Mapped[str] = mapped_column(String(30), default="service")  # webapp, api, service, database, container
    environment: Mapped[str] = mapped_column(String(20), default="production")  # production, staging, development
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    business_criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1 (baixa) a 5 (crítica)
    data_classification: Mapped[str] = mapped_column(String(20), default="internal")  # public, internal, confidential, restricted
    owner: Mapped[str] = mapped_column(String(120), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class AssetDependency(Base):
    __tablename__ = "asset_dependencies"
    __table_args__ = (UniqueConstraint("source_id", "target_id", name="uq_dependency"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    target_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    relation: Mapped[str] = mapped_column(String(40), default="calls")  # calls, reads, writes, runs_on


class ScanImport(Base):
    __tablename__ = "scan_imports"

    id: Mapped[int] = mapped_column(primary_key=True)
    scanner: Mapped[str] = mapped_column(String(30))
    filename: Mapped[str] = mapped_column(String(255), default="")
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    raw_count: Mapped[int] = mapped_column(Integer, default=0)
    new_findings: Mapped[int] = mapped_column(Integer, default=0)
    merged_findings: Mapped[int] = mapped_column(Integer, default=0)
    auto_resolved: Mapped[int] = mapped_column(Integer, default=0)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("asset_id", "dedup_key", name="uq_finding_asset_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    dedup_key: Mapped[str] = mapped_column(String(400))

    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(20))  # SCA, SAST, DAST, CONTAINER
    vuln_id: Mapped[str] = mapped_column(String(80), default="", index=True)  # CVE ou id da regra
    cwe: Mapped[str] = mapped_column(String(20), default="")
    package: Mapped[str] = mapped_column(String(200), default="")
    installed_version: Mapped[str] = mapped_column(String(80), default="")
    fixed_version: Mapped[str] = mapped_column(String(80), default="")
    location: Mapped[str] = mapped_column(String(500), default="")
    references: Mapped[list] = mapped_column(JSON, default=list)

    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(15), default="low")  # critical, high, medium, low, info
    exploit_known: Mapped[bool] = mapped_column(Boolean, default=False)  # catálogo KEV (explorada ativamente)
    exploit_public: Mapped[bool] = mapped_column(Boolean, default=False)  # exploit público disponível

    sources: Mapped[list] = mapped_column(JSON, default=list)  # scanners que reportaram
    occurrence_count: Mapped[int] = mapped_column(Integer, default=0)
    corroborated: Mapped[bool] = mapped_column(Boolean, default=False)  # confirmada por SAST + DAST

    fp_suspected: Mapped[bool] = mapped_column(Boolean, default=False)
    fp_reason: Mapped[str] = mapped_column(String(300), default="")

    status: Mapped[str] = mapped_column(String(20), default="open")  # open, in_progress, resolved, false_positive, risk_accepted
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    priority: Mapped[str] = mapped_column(String(3), default="P4")
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)
    on_attack_path: Mapped[bool] = mapped_column(Boolean, default=False)

    ai_explanation: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="findings")
    occurrences: Mapped[list["Occurrence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Occurrence(Base):
    __tablename__ = "occurrences"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    scan_import_id: Mapped[int] = mapped_column(ForeignKey("scan_imports.id", ondelete="CASCADE"))
    scanner: Mapped[str] = mapped_column(String(30))
    location: Mapped[str] = mapped_column(String(500), default="")
    raw_severity: Mapped[str] = mapped_column(String(30), default="")
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="occurrences")


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    raw_occurrences: Mapped[int] = mapped_column(Integer, default=0)
    unique_findings: Mapped[int] = mapped_column(Integer, default=0)
    actionable: Mapped[int] = mapped_column(Integer, default=0)
    p1: Mapped[int] = mapped_column(Integer, default=0)
    p2: Mapped[int] = mapped_column(Integer, default=0)
    avg_risk: Mapped[float] = mapped_column(Float, default=0.0)
    trigger: Mapped[str] = mapped_column(String(120), default="")
