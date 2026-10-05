# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Vulnerabilidades consolidadas: listagem priorizada, triagem, IA e exportação."""

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..models import Finding
from ..schemas import FindingPatch, finding_to_dict
from ..services.ai import explain_finding
from ..services.pipeline import recalculate, take_snapshot

router = APIRouter(prefix="/api/findings", tags=["vulnerabilidades"])
ACTIVE = ("open", "in_progress")


def _query(db: Session, asset_id, priority, status, category, severity, q, include_fp, sort):
    stmt = select(Finding).options(selectinload(Finding.asset))
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if priority:
        stmt = stmt.where(Finding.priority.in_(priority.split(",")))
    if status == "active":
        stmt = stmt.where(Finding.status.in_(ACTIVE))
    elif status and status != "all":
        stmt = stmt.where(Finding.status.in_(status.split(",")))
    if category:
        stmt = stmt.where(Finding.category.in_(category.split(",")))
    if severity:
        stmt = stmt.where(Finding.severity.in_(severity.split(",")))
    if not include_fp:
        stmt = stmt.where(Finding.fp_suspected.is_(False))
    findings = list(db.scalars(stmt))
    if q:
        term = q.lower()
        findings = [
            f for f in findings
            if term in " ".join([f.title, f.vuln_id, f.cwe, f.package, f.location, f.asset.name]).lower()
        ]
    if sort == "cvss":
        findings.sort(key=lambda f: (f.cvss, f.risk_score), reverse=True)
    else:
        findings.sort(key=lambda f: (f.risk_score, f.cvss), reverse=True)
    return findings


@router.get("")
def list_findings(
    asset_id: int | None = None,
    priority: str | None = None,
    status: str | None = Query("active", description="active | all | lista separada por vírgula"),
    category: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    include_fp: bool = False,
    sort: str = Query("risk", pattern="^(risk|cvss)$"),
    db: Session = Depends(get_db),
):
    return [finding_to_dict(f) for f in _query(db, asset_id, priority, status, category, severity, q, include_fp, sort)]


@router.get("/export.csv")
def export_csv(
    status: str | None = "active",
    include_fp: bool = False,
    db: Session = Depends(get_db),
):
    findings = _query(db, None, None, status, None, None, None, include_fp, "risk")
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["Prioridade", "Score", "CVSS", "Ativo", "Título", "Identificador", "CWE", "Categoria",
                     "Pacote", "Versão instalada", "Versão corrigida", "Local", "Scanners", "KEV",
                     "Exploit público", "Caminho de ataque", "Status"])
    for f in findings:
        writer.writerow([f.priority, f.risk_score, f.cvss, f.asset.name, f.title, f.vuln_id, f.cwe, f.category,
                         f.package, f.installed_version, f.fixed_version, f.location, "+".join(f.sources),
                         "sim" if f.exploit_known else "não", "sim" if f.exploit_public else "não",
                         "sim" if f.on_attack_path else "não", f.status])
    buf.seek(0)
    name = f"nexus-vulnerabilidades-{datetime.now(timezone.utc):%Y%m%d}.csv"
    return StreamingResponse(
        iter(["﻿" + buf.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


def _get(db: Session, finding_id: int) -> Finding:
    f = db.get(Finding, finding_id, options=[selectinload(Finding.asset), selectinload(Finding.occurrences)])
    if not f:
        raise HTTPException(404, "Vulnerabilidade não encontrada.")
    return f


@router.get("/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    return finding_to_dict(_get(db, finding_id), detail=True)


@router.patch("/{finding_id}")
def update_status(finding_id: int, body: FindingPatch, db: Session = Depends(get_db)):
    f = _get(db, finding_id)
    f.status = body.status
    f.resolved_at = datetime.now(timezone.utc) if body.status == "resolved" else None
    recalculate(db)
    take_snapshot(db, f"Status alterado: #{f.id} -> {body.status}")
    db.commit()
    return finding_to_dict(f, detail=True)


@router.post("/{finding_id}/explain")
def explain(finding_id: int, force: bool = False, db: Session = Depends(get_db)):
    f = _get(db, finding_id)
    if f.ai_explanation and not force:
        return f.ai_explanation
    f.ai_explanation = explain_finding(f, f.asset)
    db.commit()
    return f.ai_explanation
