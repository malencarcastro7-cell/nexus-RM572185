# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Schemas de entrada da API e serialização das entidades."""

from typing import Literal

from pydantic import BaseModel, Field

from .models import Asset, Finding, iso

AssetType = Literal["webapp", "api", "service", "database", "container"]
Environment = Literal["production", "staging", "development"]
DataClass = Literal["public", "internal", "confidential", "restricted"]
Status = Literal["open", "in_progress", "resolved", "false_positive", "risk_accepted"]


class AssetIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    asset_type: AssetType = "service"
    environment: Environment = "production"
    internet_exposed: bool = False
    business_criticality: int = Field(3, ge=1, le=5)
    data_classification: DataClass = "internal"
    owner: str = ""
    description: str = ""


class AssetPatch(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=120)
    asset_type: AssetType | None = None
    environment: Environment | None = None
    internet_exposed: bool | None = None
    business_criticality: int | None = Field(None, ge=1, le=5)
    data_classification: DataClass | None = None
    owner: str | None = None
    description: str | None = None


class DependencyIn(BaseModel):
    source_id: int
    target_id: int
    relation: str = "calls"


class FindingPatch(BaseModel):
    status: Status


def asset_to_dict(a: Asset, counts: dict | None = None) -> dict:
    return {
        "id": a.id,
        "name": a.name,
        "asset_type": a.asset_type,
        "environment": a.environment,
        "internet_exposed": a.internet_exposed,
        "business_criticality": a.business_criticality,
        "data_classification": a.data_classification,
        "owner": a.owner,
        "description": a.description,
        **(counts or {}),
    }


def finding_to_dict(f: Finding, detail: bool = False) -> dict:
    data = {
        "id": f.id,
        "asset_id": f.asset_id,
        "asset": f.asset.name if f.asset else None,
        "title": f.title,
        "category": f.category,
        "vuln_id": f.vuln_id,
        "cwe": f.cwe,
        "package": f.package,
        "installed_version": f.installed_version,
        "fixed_version": f.fixed_version,
        "location": f.location,
        "cvss": f.cvss,
        "severity": f.severity,
        "exploit_known": f.exploit_known,
        "exploit_public": f.exploit_public,
        "sources": f.sources,
        "occurrence_count": f.occurrence_count,
        "corroborated": f.corroborated,
        "fp_suspected": f.fp_suspected,
        "fp_reason": f.fp_reason,
        "status": f.status,
        "risk_score": f.risk_score,
        "priority": f.priority,
        "on_attack_path": f.on_attack_path,
        "has_ai_explanation": f.ai_explanation is not None,
        "first_seen": iso(f.first_seen),
        "last_seen": iso(f.last_seen),
        "resolved_at": iso(f.resolved_at),
    }
    if detail:
        data.update(
            {
                "description": f.description,
                "references": f.references,
                "risk_factors": f.risk_factors,
                "ai_explanation": f.ai_explanation,
                "occurrences": [
                    {
                        "scanner": o.scanner,
                        "location": o.location,
                        "raw_severity": o.raw_severity,
                        "seen_at": iso(o.seen_at),
                    }
                    for o in f.occurrences
                ],
            }
        )
    return data
