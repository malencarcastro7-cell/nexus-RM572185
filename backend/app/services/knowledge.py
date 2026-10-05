# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Acesso à base de conhecimento (CWE / OWASP / MITRE ATT&CK) e à inteligência de ameaças.

É a camada de recuperação (Retrieval) da abordagem RAG: em vez de treinar um
modelo, o NEXUS recupera o conhecimento relevante e o envia como contexto à IA.
"""

import json
from functools import lru_cache
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent / "knowledge"


@lru_cache
def _kb() -> dict:
    return json.loads((KNOWLEDGE_DIR / "knowledge_base.json").read_text(encoding="utf-8"))


@lru_cache
def _intel() -> dict:
    return json.loads((KNOWLEDGE_DIR / "threat_intel.json").read_text(encoding="utf-8"))


def kev_set() -> set[str]:
    return set(_intel().get("kev", []))


def public_exploit_set() -> set[str]:
    return set(_intel().get("public_exploit", []))


def lookup_cwe(cwe: str, category: str = "") -> tuple[str, dict]:
    """Retorna (cwe_usado, entrada). Componentes sem CWE caem em CWE-1035."""
    kb = _kb()
    if cwe and cwe in kb["cwe"]:
        return cwe, kb["cwe"][cwe]
    if category in {"SCA", "CONTAINER"}:
        return "CWE-1035", kb["cwe"]["CWE-1035"]
    return cwe or "N/A", kb["default"]


def retrieve_context(finding) -> dict:
    """Monta o pacote de contexto recuperado para uma vulnerabilidade."""
    cwe_used, entry = lookup_cwe(finding.cwe, finding.category)
    return {
        "cwe": cwe_used,
        "cwe_name": entry["name"],
        "owasp": entry["owasp"],
        "mitre_attack": entry["attack"],
        "summary": entry["summary"],
        "impact": entry["impact"],
        "remediation": entry["remediation"],
        "secure_example": entry["secure_example"],
        "kev": finding.vuln_id in kev_set(),
        "public_exploit": finding.vuln_id in public_exploit_set() or finding.exploit_public,
    }
