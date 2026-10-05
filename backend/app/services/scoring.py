# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Score de risco contextual (0 a 100).

    Severidade técnica   CVSS x 4                          até 40
    Explorabilidade      KEV 20 | exploit público 12       até 20
    Exposição            internet 20 | alcançável 10       até 20 (*)
    Impacto no negócio   criticidade x 3 + dados (0..5)    até 20 (*)
    Bônus                SAST+DAST +5 | caminho de ataque +5
    Ambiente             produção 1.0 | homologação 0.7 | dev 0.5
    Falso positivo       x 0.4

    (*) ponderados por max(0.3, CVSS/7) quando CVSS < 7 e não há exploit,
        para que um achado leve em sistema crítico não vire P1.

    Prioridade: P1 >= 75 | P2 >= 55 | P3 >= 35 | P4 < 35

Exemplo do produto: uma CVE 9.8 em sistema interno de baixa criticidade fica
abaixo de uma CVE 6.1 com exploit público em um portal financeiro exposto.
"""

from ..models import Asset, Finding

DATA_POINTS = {"restricted": 5, "confidential": 3, "internal": 1, "public": 0}
ENV_FACTOR = {"production": 1.0, "staging": 0.7, "development": 0.5}
ENV_LABEL = {"production": "produção", "staging": "homologação", "development": "desenvolvimento"}
DATA_LABEL = {"restricted": "restritos", "confidential": "confidenciais", "internal": "internos", "public": "públicos"}


def priority_for(score: float) -> str:
    if score >= 75:
        return "P1"
    if score >= 55:
        return "P2"
    if score >= 35:
        return "P3"
    return "P4"


def score_finding(f: Finding, asset: Asset, reachable: bool, on_path: bool) -> tuple[float, str, list[dict]]:
    factors: list[dict] = []

    technical = round(min(f.cvss, 10.0) * 4, 1)
    factors.append({"label": "Severidade técnica", "points": technical, "detail": f"CVSS {f.cvss:.1f}"})

    if f.exploit_known:
        exploit, detail = 20, "Explorada ativamente (catálogo CISA KEV)"
    elif f.exploit_public:
        exploit, detail = 12, "Exploit público disponível"
    else:
        exploit, detail = 0, "Sem exploit público conhecido"
    factors.append({"label": "Explorabilidade", "points": exploit, "detail": detail})

    # Contexto pesa menos em falhas de baixa severidade sem exploit: um cabeçalho
    # ausente num sistema crítico não deve competir com um RCE.
    relevance = 1.0 if (f.cvss >= 7.0 or f.exploit_known or f.exploit_public) else max(0.3, f.cvss / 7.0)
    weighted = " (ponderado pela baixa severidade)" if relevance < 1.0 else ""

    if asset.internet_exposed:
        exposure, detail = 20, "Ativo exposto diretamente à internet"
    elif reachable:
        exposure, detail = 10, "Alcançável a partir de um ativo exposto"
    else:
        exposure, detail = 0, "Ativo interno, sem rota a partir da internet"
    exposure = round(exposure * relevance, 1)
    factors.append({"label": "Exposição", "points": exposure, "detail": detail + (weighted if exposure else "")})

    business = round((asset.business_criticality * 3 + DATA_POINTS.get(asset.data_classification, 1)) * relevance, 1)
    factors.append(
        {
            "label": "Impacto no negócio",
            "points": business,
            "detail": f"Criticidade {asset.business_criticality}/5, dados "
            f"{DATA_LABEL.get(asset.data_classification, asset.data_classification)}{weighted}",
        }
    )

    score = technical + exploit + exposure + business

    if f.corroborated:
        score += 5
        factors.append({"label": "Confirmação cruzada", "points": 5, "detail": "Confirmada por SAST e DAST"})
    if on_path:
        score += 5
        factors.append({"label": "Caminho de ataque", "points": 5, "detail": "Viabiliza um caminho até uma joia da coroa"})
    if len(f.sources) > 1:
        factors.append({"label": "Correlação", "points": 0, "detail": f"Reportada por {len(f.sources)} scanners: {', '.join(f.sources)}"})

    env = ENV_FACTOR.get(asset.environment, 1.0)
    if env != 1.0:
        factors.append({"label": "Ambiente", "points": round(score * env - score, 1), "detail": f"Ambiente de {ENV_LABEL.get(asset.environment)} (x{env})"})
        score *= env

    if f.fp_suspected:
        reduced = score * 0.4
        factors.append({"label": "Provável falso positivo", "points": round(reduced - score, 1), "detail": f.fp_reason})
        score = reduced

    score = round(max(0.0, min(100.0, score)), 1)
    return score, priority_for(score), factors
