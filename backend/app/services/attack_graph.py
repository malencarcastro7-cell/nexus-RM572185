# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Attack Path Analysis.

O NEXUS monta um grafo dirigido:
    INTERNET -> ativos expostos -> dependências (APIs, serviços, bancos)

Um caminho de ataque é VIÁVEL quando cada ativo intermediário possui ao menos
uma vulnerabilidade explorável (aberta, não suspeita de falso positivo e com
CVSS >= 7, exploit público ou presença no catálogo KEV). O destino é sempre uma
"joia da coroa": banco de dados ou ativo com dados restritos.

Probabilidade de comprometimento de cada salto:
    KEV = 0.90 | exploit público = 0.70 | demais = CVSS/10 * 0.6
A probabilidade do caminho é o produto dos saltos.
"""

from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Asset, AssetDependency, Finding

INTERNET = 0
MAX_DEPTH = 6
ACTIVE_STATUSES = {"open", "in_progress"}


def is_exploitable(f: Finding) -> bool:
    return (
        f.status in ACTIVE_STATUSES
        and not f.fp_suspected
        and (f.cvss >= 7.0 or f.exploit_known or f.exploit_public)
    )


def hop_probability(f: Finding) -> float:
    if f.exploit_known:
        return 0.90
    if f.exploit_public:
        return 0.70
    return round(min(f.cvss, 10.0) / 10 * 0.6, 3)


def is_crown_jewel(asset: Asset) -> bool:
    return asset.asset_type == "database" or asset.data_classification == "restricted"


@dataclass
class GraphData:
    assets: dict[int, Asset]
    edges: dict[int, list[tuple[int, str]]] = field(default_factory=lambda: defaultdict(list))
    findings_by_asset: dict[int, list[Finding]] = field(default_factory=lambda: defaultdict(list))


def load_graph(db: Session) -> GraphData:
    assets = {a.id: a for a in db.scalars(select(Asset))}
    graph = GraphData(assets=assets)
    for a in assets.values():
        if a.internet_exposed:
            graph.edges[INTERNET].append((a.id, "exposto à internet"))
    for dep in db.scalars(select(AssetDependency)):
        if dep.source_id in assets and dep.target_id in assets:
            graph.edges[dep.source_id].append((dep.target_id, dep.relation))
    for f in db.scalars(select(Finding)):
        graph.findings_by_asset[f.asset_id].append(f)
    return graph


def reachable_from_internet(graph: GraphData) -> set[int]:
    """Ativos alcançáveis a partir de um ativo exposto (sem considerar vulnerabilidades)."""
    seen: set[int] = set()
    stack = [aid for aid, _ in graph.edges[INTERNET]]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(t for t, _ in graph.edges.get(node, []))
    return seen


def _best_entry_finding(findings: list[Finding]) -> Finding | None:
    candidates = [f for f in findings if is_exploitable(f)]
    if not candidates:
        return None
    return max(candidates, key=lambda f: (hop_probability(f), f.cvss))


def find_attack_paths(graph: GraphData) -> list[dict]:
    paths: list[dict] = []

    def dfs(node: int, trail: list[tuple[int, str]]):
        if len(trail) > MAX_DEPTH:
            return
        asset = graph.assets[node]
        visited = {n for n, _ in trail}
        if is_crown_jewel(asset):
            path = _build_path(graph, trail)
            if path:
                paths.append(path)
        # Para continuar além deste ativo, ele precisa ser comprometível.
        if _best_entry_finding(graph.findings_by_asset.get(node, [])) is None:
            return
        for nxt, relation in graph.edges.get(node, []):
            if nxt not in visited:
                dfs(nxt, trail + [(nxt, relation)])

    for entry, relation in graph.edges[INTERNET]:
        dfs(entry, [(entry, relation)])

    paths.sort(key=lambda p: p["risk_score"], reverse=True)
    for i, p in enumerate(paths, start=1):
        p["id"] = i
    return paths


def _build_path(graph: GraphData, trail: list[tuple[int, str]]) -> dict | None:
    steps = []
    probability = 1.0
    for idx, (asset_id, relation) in enumerate(trail):
        asset = graph.assets[asset_id]
        is_target = idx == len(trail) - 1
        best = _best_entry_finding(graph.findings_by_asset.get(asset_id, []))
        if best is None and not is_target:
            return None
        if best is not None and not is_target:
            probability *= hop_probability(best)
        steps.append(
            {
                "asset_id": asset.id,
                "asset_name": asset.name,
                "asset_type": asset.asset_type,
                "relation": relation,
                "is_target": is_target,
                "finding": None
                if best is None
                else {
                    "id": best.id,
                    "title": best.title,
                    "vuln_id": best.vuln_id,
                    "cvss": best.cvss,
                    "exploit_known": best.exploit_known,
                    "exploit_public": best.exploit_public,
                    "probability": hop_probability(best),
                },
            }
        )
    target = graph.assets[trail[-1][0]]
    impact = target.business_criticality / 5
    return {
        "entry": steps[0]["asset_name"],
        "target": target.name,
        "target_classification": target.data_classification,
        "length": len(steps),
        "probability": round(probability, 3),
        "impact": target.business_criticality,
        "risk_score": round(probability * impact * 100, 1),
        "steps": steps,
        "narrative": _narrative(steps, target),
        "finding_ids": [s["finding"]["id"] for s in steps if s["finding"] and not s["is_target"]],
    }


def _narrative(steps: list[dict], target: Asset) -> str:
    hops = [f"explora {s['finding']['vuln_id'] or s['finding']['title']} em {s['asset_name']}" for s in steps[:-1]]
    labels = {"restricted": "restritos", "confidential": "confidenciais", "internal": "internos", "public": "públicos"}
    end = f"alcança {target.name} (dados {labels.get(target.data_classification, target.data_classification)})."
    return "Um atacante na internet " + ", ".join(hops) + " e " + end
