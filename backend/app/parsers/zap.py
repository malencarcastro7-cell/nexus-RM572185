# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Parser do relatório JSON do OWASP ZAP (Traditional JSON Report)."""

import re
from urllib.parse import urlparse

from .base import NormalizedFinding, normalize_cwe, severity_from_cvss

# ZAP não informa CVSS; estimamos a partir do riskcode (0=Info, 1=Low, 2=Medium, 3=High).
RISK_TO_CVSS = {"3": 7.5, "2": 5.3, "1": 3.1, "0": 0.0}
CONFIDENCE = {"0": "false positive", "1": "low", "2": "medium", "3": "high", "4": "confirmed"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
CVSS_HINT = {"CVE-2020-11022": 6.1, "CVE-2020-11023": 6.1, "CVE-2019-11358": 6.1}


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text or "").strip()


def parse(report: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for site in report.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            riskcode = str(alert.get("riskcode", "0"))
            confidence = CONFIDENCE.get(str(alert.get("confidence", "2")), "medium")
            description = _strip_html(alert.get("desc", ""))
            other = _strip_html(alert.get("otherinfo", ""))
            cves = CVE_RE.findall(" ".join([description, other, alert.get("reference", "")]))
            name = alert.get("name") or alert.get("alert") or "Alerta DAST"
            instances = alert.get("instances") or [{"uri": site.get("@name", ""), "method": "", "param": ""}]
            for inst in instances:
                uri = inst.get("uri", "")
                path = urlparse(uri).path or "/"
                param = inst.get("param", "")
                cvss = RISK_TO_CVSS.get(riskcode, 0.0)
                if cves:
                    cvss = CVSS_HINT.get(cves[0], cvss)
                findings.append(
                    NormalizedFinding(
                        scanner="zap",
                        category="DAST",
                        title=name,
                        description=description,
                        vuln_id=cves[0] if cves else f"ZAP-{alert.get('pluginid', '')}",
                        cwe=normalize_cwe(alert.get("cweid")),
                        location=f"{inst.get('method', 'GET') or 'GET'} {path}" + (f" [param: {param}]" if param else ""),
                        cvss=cvss,
                        severity=severity_from_cvss(cvss),
                        exploit_public=bool(cves),
                        references=[r for r in re.split(r"\s+", _strip_html(alert.get("reference", ""))) if r.startswith("http")],
                        raw_severity=f"risk {riskcode} / confidence {confidence}",
                        extra={
                            "confidence": confidence,
                            "solution": _strip_html(alert.get("solution", "")),
                            "url": uri,
                            "param": param,
                            "plugin_id": alert.get("pluginid", ""),
                        },
                    )
                )
    return findings
