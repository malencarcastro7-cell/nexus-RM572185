# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Parser do relatório JSON do Trivy (`trivy image -f json` / `trivy fs -f json`)."""

from .base import SEVERITY_TO_CVSS, NormalizedFinding, normalize_cwe, severity_from_cvss


def _best_cvss(cvss_block: dict) -> float:
    if not isinstance(cvss_block, dict):
        return 0.0
    # Preferência: NVD, depois o fornecedor que tiver nota v3.
    ordered = ["nvd", "ghsa", "redhat"] + [k for k in cvss_block if k not in {"nvd", "ghsa", "redhat"}]
    for source in ordered:
        data = cvss_block.get(source) or {}
        score = data.get("V3Score") or data.get("V40Score") or data.get("V2Score")
        if score:
            return float(score)
    return 0.0


def parse(report: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    artifact = report.get("ArtifactName", "")
    for result in report.get("Results", []) or []:
        target = result.get("Target", artifact)
        result_class = result.get("Class", "")
        category = "CONTAINER" if result_class == "os-pkgs" else "SCA"
        for vuln in result.get("Vulnerabilities", []) or []:
            raw_sev = (vuln.get("Severity") or "UNKNOWN").lower()
            cvss = _best_cvss(vuln.get("CVSS", {}))
            if not cvss:
                cvss = SEVERITY_TO_CVSS.get(raw_sev, 0.0)
            cwes = vuln.get("CweIDs") or []
            refs = [vuln["PrimaryURL"]] if vuln.get("PrimaryURL") else []
            findings.append(
                NormalizedFinding(
                    scanner="trivy",
                    category=category,
                    title=vuln.get("Title") or f"{vuln.get('VulnerabilityID')} em {vuln.get('PkgName')}",
                    description=vuln.get("Description", ""),
                    vuln_id=vuln.get("VulnerabilityID", ""),
                    cwe=normalize_cwe(cwes[0]) if cwes else "",
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", ""),
                    location=target,
                    cvss=cvss,
                    severity=severity_from_cvss(cvss),
                    references=refs,
                    raw_severity=raw_sev,
                    extra={"class": result_class, "type": result.get("Type", "")},
                )
            )
    return findings
