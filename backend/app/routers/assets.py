# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Inventário de ativos e grafo de dependências.

Qualquer alteração de contexto (exposição, criticidade, dependências) dispara o
recálculo de risco de todas as vulnerabilidades.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Asset, AssetDependency, Finding
from ..schemas import AssetIn, AssetPatch, DependencyIn, asset_to_dict
from ..services.pipeline import recalculate, take_snapshot

router = APIRouter(prefix="/api", tags=["ativos"])
ACTIVE = {"open", "in_progress"}


def _counts(db: Session) -> dict[int, dict]:
    counts: dict[int, dict] = {}
    for f in db.scalars(select(Finding)):
        c = counts.setdefault(f.asset_id, {"open_findings": 0, "p1": 0, "max_risk": 0.0})
        if f.status in ACTIVE and not f.fp_suspected:
            c["open_findings"] += 1
            c["p1"] += f.priority == "P1"
            c["max_risk"] = max(c["max_risk"], f.risk_score)
    return counts


@router.get("/assets")
def list_assets(db: Session = Depends(get_db)):
    counts = _counts(db)
    empty = {"open_findings": 0, "p1": 0, "max_risk": 0.0}
    return [asset_to_dict(a, counts.get(a.id, empty)) for a in db.scalars(select(Asset).order_by(Asset.name))]


@router.post("/assets", status_code=201)
def create_asset(body: AssetIn, db: Session = Depends(get_db)):
    asset = Asset(**body.model_dump())
    db.add(asset)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Já existe um ativo com esse nome.")
    db.commit()
    return asset_to_dict(asset)


@router.patch("/assets/{asset_id}")
def update_asset(asset_id: int, body: AssetPatch, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Ativo não encontrado.")
    changes = body.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(asset, key, value)
    recalculate(db)
    take_snapshot(db, f"Contexto alterado: {asset.name}")
    db.commit()
    return asset_to_dict(asset, _counts(db).get(asset.id))


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Ativo não encontrado.")
    for dep in db.scalars(
        select(AssetDependency).where(
            (AssetDependency.source_id == asset_id) | (AssetDependency.target_id == asset_id)
        )
    ):
        db.delete(dep)
    db.delete(asset)
    db.flush()
    recalculate(db)
    db.commit()


@router.get("/dependencies")
def list_dependencies(db: Session = Depends(get_db)):
    return [
        {"id": d.id, "source_id": d.source_id, "target_id": d.target_id, "relation": d.relation}
        for d in db.scalars(select(AssetDependency))
    ]


@router.post("/dependencies", status_code=201)
def create_dependency(body: DependencyIn, db: Session = Depends(get_db)):
    if body.source_id == body.target_id:
        raise HTTPException(400, "Origem e destino devem ser diferentes.")
    if not db.get(Asset, body.source_id) or not db.get(Asset, body.target_id):
        raise HTTPException(404, "Ativo não encontrado.")
    dep = AssetDependency(**body.model_dump())
    db.add(dep)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Essa dependência já existe.")
    recalculate(db)
    take_snapshot(db, "Dependência adicionada")
    db.commit()
    return {"id": dep.id, **body.model_dump()}


@router.delete("/dependencies/{dep_id}", status_code=204)
def delete_dependency(dep_id: int, db: Session = Depends(get_db)):
    dep = db.get(AssetDependency, dep_id)
    if not dep:
        raise HTTPException(404, "Dependência não encontrada.")
    db.delete(dep)
    db.flush()
    recalculate(db)
    take_snapshot(db, "Dependência removida")
    db.commit()
