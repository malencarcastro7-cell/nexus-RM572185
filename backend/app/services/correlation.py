# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Motor de correlação: deduplicação, heurísticas de falso positivo e consolidação.

Regras de deduplicação (chave por ativo):
- SCA / CONTAINER com CVE: CVE + nome do pacote (sem groupId). Assim o mesmo
  CVE do Log4j reportado pelo Trivy e pelo Snyk vira UMA vulnerabilidade.
- DAST sem parâmetro (ex.: cabeçalho ausente): consolidado por regra no site
  inteiro, porque é um problema de configuração único.
- DAST com parâmetro: regra + caminho + parâmetro.
- SAST: regra + arquivo + linha.
"""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Asset, Finding, Occurrence, ScanImport
from ..parsers import NormalizedFinding
from ..parsers.base import SEVERITY_ORDER
from .knowledge import kev_set, public_exploit_set

TEST_PATH_MARKERS = ("/test/", "src/test", "/tests/", "__tests__", "/spec/", "/fixtures/", "/mocks/")
TEST_ONLY_LIBS = {"junit", "mockito-core", "testng", "jest", "mocha", "pytest", "hamcrest-core", "assertj-core"}


def _artifact(package: str) -> str:
    name = package.lower().strip()
    for sep in (":", "/"):
        if sep in name:
            name = name.rsplit(sep, 1)[-1]
    return name


def dedup_key(nf: NormalizedFinding) -> str:
    vuln = (nf.vuln_id or "").upper()
    if nf.category in {"SCA", "CONTAINER"}:
        return f"{vuln}|{_artifact(nf.package)}"
    if nf.category == "DAST":
        if vuln.startswith("CVE-"):
            return f"DAST|{vuln}"
        param = nf.extra.get("param", "")
        if not param:
            return f"DAST|{vuln}|site"
        path = nf.location.split(" [param")[0]
        return f"DAST|{vuln}|{path}|{param}"
    # SAST
    return f"SAST|{vuln}|{nf.location}"


def false_positive_reason(nf: NormalizedFinding) -> str:
    location = (nf.location or "").lower()
    if any(marker in location for marker in TEST_PATH_MARKERS):
        return "Encontrada em código de teste, que não é implantado em produção."
    if nf.category == "SCA" and _artifact(nf.package) in TEST_ONLY_LIBS:
        return "Dependência usada apenas em testes (não faz parte do artefato de produção)."
    if nf.category == "DAST" and nf.extra.get("confidence") in {"low", "false positive"}:
        return "Confiança baixa reportada pelo próprio scanner DAST."
    if nf.severity == "info":
        return "Achado apenas informativo, sem impacto de segurança direto."
    return ""


def _max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


def import_findings(
    db: Session, asset: Asset, scanner: str, filename: str, normalized: list[NormalizedFinding]
) -> ScanImport:
    now = datetime.now(timezone.utc)
    kev, public = kev_set(), public_exploit_set()

    scan = ScanImport(scanner=scanner, filename=filename, asset_id=asset.id, raw_count=len(normalized))
    db.add(scan)
    db.flush()

    existing = {f.dedup_key: f for f in db.scalars(select(Finding).where(Finding.asset_id == asset.id))}
    seen_keys: set[str] = set()
    new_count = merged_count = 0

    for nf in normalized:
        key = dedup_key(nf)
        seen_keys.add(key)
        finding = existing.get(key)
        if finding is None:
            reason = false_positive_reason(nf)
            finding = Finding(
                asset_id=asset.id,
                dedup_key=key,
                title=nf.title[:300],
                description=nf.description,
                category=nf.category,
                vuln_id=nf.vuln_id,
                cwe=nf.cwe,
                package=nf.package,
                installed_version=nf.installed_version,
                fixed_version=nf.fixed_version,
                location=nf.location[:500],
                references=nf.references[:10],
                cvss=nf.cvss,
                severity=nf.severity,
                exploit_known=nf.vuln_id in kev,
                exploit_public=nf.exploit_public or nf.vuln_id in public,
                sources=[scanner],
                occurrence_count=0,
                fp_suspected=bool(reason),
                fp_reason=reason,
                first_seen=now,
                last_seen=now,
            )
            db.add(finding)
            db.flush()
            existing[key] = finding
            new_count += 1
        else:
            merged_count += 1
            if scanner not in finding.sources:
                finding.sources = [*finding.sources, scanner]
            finding.cvss = max(finding.cvss, nf.cvss)
            finding.severity = _max_severity(finding.severity, nf.severity)
            finding.exploit_public = finding.exploit_public or nf.exploit_public
            finding.fixed_version = finding.fixed_version or nf.fixed_version
            finding.cwe = finding.cwe or nf.cwe
            if len(nf.description) > len(finding.description or ""):
                finding.description = nf.description
            finding.last_seen = now
            if finding.status == "resolved":  # reapareceu: reabre
                finding.status = "open"
                finding.resolved_at = None
                finding.ai_explanation = None

        finding.occurrence_count += 1
        db.add(
            Occurrence(
                finding_id=finding.id,
                scan_import_id=scan.id,
                scanner=scanner,
                location=nf.location[:500],
                raw_severity=nf.raw_severity[:30],
                seen_at=now,
            )
        )

    # Correção detectada: vulnerabilidade que só este scanner reportava e sumiu do novo relatório.
    auto_resolved = 0
    for finding in existing.values():
        if (
            finding.dedup_key not in seen_keys
            and finding.sources == [scanner]
            and finding.status in {"open", "in_progress"}
        ):
            finding.status = "resolved"
            finding.resolved_at = now
            auto_resolved += 1

    scan.new_findings = new_count
    scan.merged_findings = merged_count
    scan.auto_resolved = auto_resolved
    update_corroboration(db, asset.id)
    db.flush()
    return scan


def update_corroboration(db: Session, asset_id: int) -> None:
    """Marca vulnerabilidades confirmadas por análise estática E dinâmica (mesmo CWE, mesmo ativo)."""
    findings = list(db.scalars(select(Finding).where(Finding.asset_id == asset_id)))
    sast_cwes = {f.cwe for f in findings if f.category == "SAST" and f.cwe and not f.fp_suspected}
    dast_cwes = {f.cwe for f in findings if f.category == "DAST" and f.cwe and not f.fp_suspected}
    both = sast_cwes & dast_cwes
    for f in findings:
        f.corroborated = f.cwe in both and f.category in {"SAST", "DAST"} and not f.fp_suspected
