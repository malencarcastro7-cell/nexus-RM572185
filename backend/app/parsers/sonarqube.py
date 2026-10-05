# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Parser da API de issues do SonarQube (`/api/issues/search?types=VULNERABILITY`)."""

from .base import NormalizedFinding, severity_from_cvss

SEVERITY_TO_CVSS = {"BLOCKER": 9.0, "CRITICAL": 7.5, "MAJOR": 5.5, "MINOR": 3.0, "INFO": 0.0}

# Mapeamento das regras de segurança mais comuns do SonarQube para CWE.
RULE_TO_CWE = {
    "S3649": "CWE-89",   # SQL Injection
    "S5131": "CWE-79",   # XSS
    "S2076": "CWE-78",   # OS Command Injection
    "S2083": "CWE-22",   # Path Traversal
    "S5144": "CWE-918",  # SSRF
    "S5145": "CWE-117",  # Log Injection
    "S2068": "CWE-798",  # Credenciais em código
    "S6437": "CWE-798",
    "S4790": "CWE-328",  # Hash fraco
    "S2245": "CWE-338",  # PRNG fraco
    "S5332": "CWE-319",  # Texto claro
    "S4507": "CWE-489",  # Debug ativo
    "S2755": "CWE-611",  # XXE
    "S5135": "CWE-502",  # Desserialização
}


def _rule_cwe(rule: str) -> str:
    key = rule.split(":")[-1].upper()
    return RULE_TO_CWE.get(key, "")


def parse(report: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    issues = list(report.get("issues", []) or []) + list(report.get("hotspots", []) or [])
    for issue in issues:
        rule = issue.get("rule") or issue.get("ruleKey") or ""
        raw_sev = (issue.get("severity") or issue.get("vulnerabilityProbability") or "MAJOR").upper()
        if raw_sev in {"HIGH", "MEDIUM", "LOW"}:  # hotspots
            raw_sev = {"HIGH": "CRITICAL", "MEDIUM": "MAJOR", "LOW": "MINOR"}[raw_sev]
        cvss = SEVERITY_TO_CVSS.get(raw_sev, 5.5)
        component = issue.get("component", "")
        project = issue.get("project", "")
        if project and component.startswith(project + ":"):
            path = component[len(project) + 1:]
        else:
            path = component.rsplit(":", 1)[-1]
        line = issue.get("line")
        findings.append(
            NormalizedFinding(
                scanner="sonarqube",
                category="SAST",
                title=issue.get("message", "Vulnerabilidade de código"),
                description=issue.get("message", ""),
                vuln_id=rule,
                cwe=_rule_cwe(rule),
                location=f"{path}:{line}" if line else path,
                cvss=cvss,
                severity=severity_from_cvss(cvss),
                raw_severity=raw_sev,
                extra={"issue_key": issue.get("key", ""), "file": path, "line": line},
            )
        )
    return findings
