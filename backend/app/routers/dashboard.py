# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Indicadores executivos, correlação entre aplicações, caminhos de ataque e IA."""

from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..models import Asset, Finding, Occurrence, RiskSnapshot, iso
from ..services.ai import executive_summary, provider_info
from ..services.attack_graph import find_attack_paths, load_graph

router = APIRouter(prefix="/api", tags=["dashboard"])
ACTIVE = {"open", "in_progress"}


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def compute_stats(db: Session) -> dict:
    findings = list(db.scalars(select(Finding).options(selectinload(Finding.asset))))
    raw = db.scalar(select(func.count(Occurrence.id))) or 0
    active = [f for f in findings if f.status in ACTIVE]
    actionable = [f for f in active if not f.fp_suspected]
    fp_suspected = [f for f in active if f.fp_suspected]
    resolved = [f for f in findings if f.status == "resolved" and f.resolved_at]

    mttr_days = None
    if resolved:
        durations = [(_aware(f.resolved_at) - _aware(f.first_seen)).total_seconds() / 86400 for f in resolved]
        mttr_days = round(sum(durations) / len(durations), 1)

    def count_by(items, attr, keys):
        out = {k: 0 for k in keys}
        for f in items:
            out[getattr(f, attr)] = out.get(getattr(f, attr), 0) + 1
        return out

    return {
        "raw_occurrences": raw,
        "unique_findings": len(findings),
        "active": len(active),
        "actionable": len(actionable),
        "fp_suspected": len(fp_suspected),
        "duplicates_removed": max(raw - len(findings), 0),
        "noise_reduction_pct": round((1 - len(actionable) / raw) * 100, 1) if raw else 0.0,
        "p1": sum(1 for f in actionable if f.priority == "P1"),
        "kev_open": sum(1 for f in actionable if f.exploit_known),
        "on_attack_path": sum(1 for f in actionable if f.on_attack_path),
        "resolved": len(resolved),
        "mttr_days": mttr_days,
        "by_priority": count_by(actionable, "priority", ["P1", "P2", "P3", "P4"]),
        "by_severity": count_by(actionable, "severity", ["critical", "high", "medium", "low", "info"]),
        "by_category": count_by(actionable, "category", ["SCA", "CONTAINER", "SAST", "DAST"]),
        "_actionable": actionable,
    }


def _top(actionable: list[Finding], n: int = 5) -> list[dict]:
    ranked = sorted(actionable, key=lambda f: f.risk_score, reverse=True)[:n]
    return [
        {"id": f.id, "title": f.title, "vuln_id": f.vuln_id, "asset": f.asset.name, "risk_score": f.risk_score,
         "priority": f.priority, "cvss": f.cvss, "severity": f.severity, "exploit_known": f.exploit_known,
         "on_attack_path": f.on_attack_path}
        for f in ranked
    ]


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    stats = compute_stats(db)
    actionable = stats.pop("_actionable")

    # Correlação de CVEs entre aplicações: mesmo CVE presente em mais de um ativo.
    by_cve: dict[str, list[Finding]] = defaultdict(list)
    for f in actionable:
        if f.vuln_id.startswith("CVE-"):
            by_cve[f.vuln_id].append(f)
    cross_app = sorted(
        (
            {
                "vuln_id": cve,
                "title": items[0].title,
                "package": items[0].package,
                "cvss": max(i.cvss for i in items),
                "exploit_known": any(i.exploit_known for i in items),
                "assets": sorted({i.asset.name for i in items}),
                "max_risk": max(i.risk_score for i in items),
            }
            for cve, items in by_cve.items()
            if len({i.asset_id for i in items}) > 1
        ),
        key=lambda x: x["max_risk"],
        reverse=True,
    )

    # Contraste severidade x risco: o que o CVSS sozinho esconde.
    by_cvss = sorted(actionable, key=lambda f: f.cvss, reverse=True)[:5]
    snapshots = db.scalars(select(RiskSnapshot).order_by(RiskSnapshot.taken_at, RiskSnapshot.id)).all()

    return {
        "stats": stats,
        "top_risks": _top(actionable),
        "top_by_cvss_only": [
            {"id": f.id, "title": f.title, "vuln_id": f.vuln_id, "asset": f.asset.name, "cvss": f.cvss,
             "risk_score": f.risk_score, "priority": f.priority}
            for f in by_cvss
        ],
        "cross_app_cves": cross_app,
        "trend": [
            {"taken_at": iso(s.taken_at), "actionable": s.actionable, "p1": s.p1, "p2": s.p2,
             "avg_risk": s.avg_risk, "trigger": s.trigger}
            for s in snapshots[-30:]
        ],
        "assets": db.scalar(select(func.count(Asset.id))) or 0,
        "ai": provider_info(),
    }


@router.get("/attack-paths")
def attack_paths(db: Session = Depends(get_db)):
    graph = load_graph(db)
    nodes = [{"id": 0, "name": "Internet", "asset_type": "internet", "internet_exposed": True}] + [
        {"id": a.id, "name": a.name, "asset_type": a.asset_type, "internet_exposed": a.internet_exposed,
         "business_criticality": a.business_criticality, "data_classification": a.data_classification}
        for a in graph.assets.values()
    ]
    edges = [{"source": s, "target": t, "relation": r} for s, targets in graph.edges.items() for t, r in targets]
    return {"paths": find_attack_paths(graph), "nodes": nodes, "edges": edges}


@router.get("/ai/status")
def ai_status():
    return provider_info()


@router.post("/ai/executive-summary")
def ai_executive_summary(db: Session = Depends(get_db)):
    stats = compute_stats(db)
    actionable = stats.pop("_actionable")
    paths = find_attack_paths(load_graph(db))
    summary = executive_summary(stats, _top(actionable), paths)
    summary["generated_at"] = datetime.now(timezone.utc).isoformat()
    return summary
