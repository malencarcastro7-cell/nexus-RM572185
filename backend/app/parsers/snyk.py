# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Parser do relatório JSON do Snyk Open Source (`snyk test --json`)."""

from .base import SEVERITY_TO_CVSS, NormalizedFinding, normalize_cwe, severity_from_cvss

MATURE_EXPLOITS = {"mature", "functional", "proof of concept", "high"}


def parse(report: dict | list) -> list[NormalizedFinding]:
    # `snyk test --all-projects --json` devolve uma lista de projetos.
    projects = report if isinstance(report, list) else [report]
    findings: list[NormalizedFinding] = []
    for project in projects:
        manifest = project.get("displayTargetFile") or project.get("targetFile") or project.get("projectName", "")
        for vuln in project.get("vulnerabilities", []) or []:
            identifiers = vuln.get("identifiers") or {}
            cves = identifiers.get("CVE") or []
            cwes = identifiers.get("CWE") or []
            raw_sev = (vuln.get("severity") or "low").lower()
            cvss = float(vuln.get("cvssScore") or 0) or SEVERITY_TO_CVSS.get(raw_sev, 0.0)
            fixed = vuln.get("fixedIn") or []
            exploit = str(vuln.get("exploit") or vuln.get("exploitMaturity") or "").lower()
            findings.append(
                NormalizedFinding(
                    scanner="snyk",
                    category="SCA",
                    title=vuln.get("title", "Vulnerabilidade em dependência"),
                    description=vuln.get("description", ""),
                    vuln_id=cves[0] if cves else vuln.get("id", ""),
                    cwe=normalize_cwe(cwes[0]) if cwes else "",
                    package=vuln.get("packageName", ""),
                    installed_version=vuln.get("version", ""),
                    fixed_version=", ".join(fixed),
                    location=manifest,
                    cvss=cvss,
                    severity=severity_from_cvss(cvss),
                    exploit_public=exploit in MATURE_EXPLOITS,
                    references=[r.get("url") for r in vuln.get("references", []) if isinstance(r, dict) and r.get("url")],
                    raw_severity=raw_sev,
                    extra={"snyk_id": vuln.get("id", ""), "from": vuln.get("from", [])},
                )
            )
    return findings
