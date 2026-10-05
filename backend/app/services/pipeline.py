# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Recalcula a postura de risco: grafo -> caminhos de ataque -> scores -> histórico."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Finding, Occurrence, RiskSnapshot
from .attack_graph import find_attack_paths, load_graph, reachable_from_internet
from .scoring import score_finding

ACTIVE = ("open", "in_progress")


def recalculate(db: Session) -> list[dict]:
    graph = load_graph(db)
    reachable = reachable_from_internet(graph)
    paths = find_attack_paths(graph)
    on_path_ids = {fid for p in paths for fid in p["finding_ids"]}

    for asset_id, findings in graph.findings_by_asset.items():
        asset = graph.assets[asset_id]
        for f in findings:
            f.on_attack_path = f.id in on_path_ids
            f.risk_score, f.priority, f.risk_factors = score_finding(
                f, asset, asset_id in reachable, f.on_attack_path
            )
    db.flush()
    return paths


def take_snapshot(db: Session, trigger: str) -> RiskSnapshot:
    active = list(db.scalars(select(Finding).where(Finding.status.in_(ACTIVE))))
    actionable = [f for f in active if not f.fp_suspected]
    snap = RiskSnapshot(
        raw_occurrences=db.scalar(select(func.count(Occurrence.id))) or 0,
        unique_findings=db.scalar(select(func.count(Finding.id))) or 0,
        actionable=len(actionable),
        p1=sum(1 for f in actionable if f.priority == "P1"),
        p2=sum(1 for f in actionable if f.priority == "P2"),
        avg_risk=round(sum(f.risk_score for f in actionable) / len(actionable), 1) if actionable else 0.0,
        trigger=trigger[:120],
    )
    db.add(snap)
    db.flush()
    return snap
