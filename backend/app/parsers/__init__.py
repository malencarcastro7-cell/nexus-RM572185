# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Registro de parsers e detecção automática do formato do relatório."""

from . import snyk, sonarqube, trivy, zap
from .base import NormalizedFinding

PARSERS = {
    "trivy": trivy.parse,
    "snyk": snyk.parse,
    "zap": zap.parse,
    "sonarqube": sonarqube.parse,
}

SUPPORTED_SCANNERS = list(PARSERS)


def detect_scanner(report) -> str | None:
    """Identifica o scanner pela estrutura do JSON."""
    if isinstance(report, list):
        return "snyk" if report and isinstance(report[0], dict) and "vulnerabilities" in report[0] else None
    if not isinstance(report, dict):
        return None
    if "Results" in report and ("SchemaVersion" in report or "ArtifactName" in report):
        return "trivy"
    if "vulnerabilities" in report and ("packageManager" in report or "projectName" in report or "ok" in report):
        return "snyk"
    if "site" in report and isinstance(report.get("site"), list):
        return "zap"
    if "issues" in report or "hotspots" in report:
        return "sonarqube"
    return None


def parse_report(report, scanner: str | None = None) -> tuple[str, list[NormalizedFinding]]:
    scanner = (scanner or "").lower() or detect_scanner(report)
    if scanner not in PARSERS:
        raise ValueError(
            "Formato de relatório não reconhecido. Suportados: " + ", ".join(SUPPORTED_SCANNERS)
        )
    return scanner, PARSERS[scanner](report)


__all__ = ["NormalizedFinding", "SUPPORTED_SCANNERS", "detect_scanner", "parse_report"]
