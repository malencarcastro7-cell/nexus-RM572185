# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Formato normalizado: todo scanner é convertido para NormalizedFinding."""

from dataclasses import dataclass, field

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class NormalizedFinding:
    scanner: str
    category: str  # SCA, SAST, DAST, CONTAINER
    title: str
    description: str = ""
    vuln_id: str = ""  # CVE-xxxx ou id da regra do scanner
    cwe: str = ""  # formato "CWE-89"
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    location: str = ""  # arquivo:linha, URL ou alvo da imagem
    cvss: float = 0.0
    severity: str = "low"
    exploit_public: bool = False
    references: list[str] = field(default_factory=list)
    raw_severity: str = ""
    extra: dict = field(default_factory=dict)


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


# Quando o scanner não informa CVSS, usamos um valor representativo da severidade.
SEVERITY_TO_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}


def normalize_cwe(value) -> str:
    if value in (None, "", "-1", -1, 0, "0"):
        return ""
    text = str(value).strip().upper()
    if text.startswith("CWE-"):
        return text
    if text.isdigit():
        return f"CWE-{text}"
    return ""
