# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Central de Ingestão: recebe relatórios dos scanners e dispara a correlação.

Pode ser chamada pelo dashboard (upload) ou por pipelines de CI/CD:

    curl -F "file=@trivy.json" -F "asset_id=2" http://localhost:8000/api/imports
"""

import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Asset, ScanImport, iso
from ..parsers import SUPPORTED_SCANNERS, parse_report
from ..services.correlation import import_findings
from ..services.pipeline import recalculate, take_snapshot

router = APIRouter(prefix="/api", tags=["ingestão"])
MAX_BYTES = 20 * 1024 * 1024


@router.get("/scanners")
def scanners():
    return [
        {"id": "trivy", "name": "Trivy", "category": "SCA / Container", "command": "trivy image -f json -o trivy.json <imagem>"},
        {"id": "snyk", "name": "Snyk Open Source", "category": "SCA", "command": "snyk test --json > snyk.json"},
        {"id": "zap", "name": "OWASP ZAP", "category": "DAST", "command": "zap-baseline.py -t <url> -J zap.json"},
        {"id": "sonarqube", "name": "SonarQube", "category": "SAST", "command": "GET /api/issues/search?types=VULNERABILITY&componentKeys=<projeto>"},
    ]


def ingest(db: Session, asset: Asset, content: bytes, filename: str, scanner: str | None) -> dict:
    try:
        report = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(400, "O arquivo precisa ser um relatório JSON válido.")
    try:
        scanner_used, normalized = parse_report(report, scanner)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    scan = import_findings(db, asset, scanner_used, filename, normalized)
    recalculate(db)
    take_snapshot(db, f"Importação {scanner_used} em {asset.name}")
    db.commit()
    return import_to_dict(scan, asset)


def import_to_dict(scan: ScanImport, asset: Asset | None = None) -> dict:
    return {
        "id": scan.id,
        "scanner": scan.scanner,
        "filename": scan.filename,
        "asset_id": scan.asset_id,
        "asset": asset.name if asset else None,
        "imported_at": iso(scan.imported_at),
        "raw_count": scan.raw_count,
        "new_findings": scan.new_findings,
        "merged_findings": scan.merged_findings,
        "auto_resolved": scan.auto_resolved,
    }


@router.post("/imports", status_code=201)
async def upload_report(
    file: UploadFile = File(...),
    asset_id: int = Form(...),
    scanner: str | None = Form(None),
    db: Session = Depends(get_db),
):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Ativo não encontrado.")
    if scanner and scanner not in SUPPORTED_SCANNERS and scanner != "auto":
        raise HTTPException(400, f"Scanner não suportado. Use: {', '.join(SUPPORTED_SCANNERS)}")
    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(413, "Arquivo maior que 20 MB.")
    return ingest(db, asset, content, file.filename or "relatorio.json", None if scanner in (None, "", "auto") else scanner)


@router.get("/imports")
def list_imports(db: Session = Depends(get_db)):
    assets = {a.id: a for a in db.scalars(select(Asset))}
    scans = db.scalars(select(ScanImport).order_by(ScanImport.imported_at.desc(), ScanImport.id.desc()))
    return [import_to_dict(s, assets.get(s.asset_id)) for s in scans]
