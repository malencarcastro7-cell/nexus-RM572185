# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""IA de priorização e remediação (RAG).

Fluxo:
1. Recupera conhecimento (CWE, OWASP Top 10, MITRE ATT&CK, KEV) da base local.
2. Junta com o contexto real: ativo, exposição, score e fatores de risco.
3. Envia à LLM configurada (OpenAI GPT-4o ou Llama 3 / Mistral via Ollama).
4. Se nenhuma LLM estiver disponível, gera a explicação no modo offline a partir
   da mesma base de conhecimento, para que a plataforma funcione sem internet.

A IA apenas RECOMENDA. Nenhuma correção é aplicada automaticamente.
"""

import json
import logging
from datetime import datetime, timezone

import httpx

from ..config import settings
from ..models import Asset, Finding
from .knowledge import retrieve_context
from .scoring import DATA_LABEL, ENV_LABEL

log = logging.getLogger("nexus.ai")

SYSTEM_PROMPT = (
    "Você é o motor de IA do NEXUS, uma plataforma ASPM. Explique vulnerabilidades para "
    "desenvolvedores e líderes em português do Brasil, de forma objetiva e prática. "
    "Use SOMENTE o contexto fornecido; não invente CVEs, versões ou fatos. "
    "Você recomenda correções, mas nunca as aplica. Responda apenas com JSON válido."
)

RESPONSE_SCHEMA_HINT = {
    "o_que_e": "explicação curta da falha (2-3 frases)",
    "por_que_perigoso": "risco neste ativo específico, citando exposição e impacto no negócio",
    "cenario_ataque": "como um atacante exploraria, em 2-3 frases",
    "como_corrigir": ["passo 1", "passo 2", "passo 3"],
    "exemplo_codigo": {"language": "linguagem", "code": "código seguro ou patch"},
    "esforco_estimado": "baixo | médio | alto, com justificativa curta",
}


def active_provider() -> str:
    p = settings.ai_provider
    if p == "auto":
        if settings.openai_api_key:
            return "openai"
        if settings.ollama_url:
            return "ollama"
        return "offline"
    return p


def provider_info() -> dict:
    provider = active_provider()
    model = {"openai": settings.openai_model, "ollama": settings.ollama_model}.get(provider, "base de conhecimento local")
    return {"provider": provider, "model": model}


# ---------------------------------------------------------------- contexto
def _ecosystem(f: Finding) -> str:
    loc = (f.location or "").lower()
    if f.category == "CONTAINER":
        return "os"
    if "package.json" in loc or "package-lock" in loc or "yarn.lock" in loc or f.category == "DAST":
        return "npm"
    if "requirements" in loc or "pipfile" in loc or "poetry" in loc:
        return "pypi"
    if ":" in (f.package or "") or loc.endswith(".jar") or "pom.xml" in loc or "gradle" in loc:
        return "maven"
    return "generic"


def suggested_patch(f: Finding) -> dict | None:
    """Gera o patch de dependência quando há versão corrigida conhecida."""
    if f.category not in {"SCA", "CONTAINER"} or not f.fixed_version:
        return None
    fixed = f.fixed_version.split(",")[-1].strip()
    eco = _ecosystem(f)
    if eco == "maven" and ":" in f.package:
        group, artifact = f.package.split(":", 1)
        code = (
            "<!-- pom.xml -->\n<dependency>\n"
            f"  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n"
            f"  <version>{fixed}</version>\n</dependency>"
        )
        return {"language": "xml", "code": code, "summary": f"Atualizar {artifact} de {f.installed_version} para {fixed}"}
    if eco == "npm":
        return {"language": "bash", "code": f"npm install {f.package}@{fixed} --save", "summary": f"Atualizar {f.package} para {fixed}"}
    if eco == "pypi":
        return {"language": "bash", "code": f"pip install '{f.package}>={fixed}'", "summary": f"Atualizar {f.package} para {fixed}"}
    if eco == "os":
        code = (
            "# Dockerfile: atualize o pacote do sistema e reconstrua a imagem\n"
            f"RUN apt-get update && apt-get install -y --only-upgrade {f.package} \\\n"
            "    && rm -rf /var/lib/apt/lists/*"
        )
        return {"language": "dockerfile", "code": code, "summary": f"Atualizar pacote {f.package} para {fixed}"}
    return {"language": "text", "code": f"Atualize {f.package} para a versão {fixed}.", "summary": f"Atualizar {f.package} para {fixed}"}


def build_context(f: Finding, asset: Asset) -> dict:
    kb = retrieve_context(f)
    return {
        "vulnerabilidade": {
            "titulo": f.title,
            "identificador": f.vuln_id,
            "categoria": f.category,
            "cwe": kb["cwe"],
            "cvss": f.cvss,
            "severidade": f.severity,
            "pacote": f.package,
            "versao_instalada": f.installed_version,
            "versao_corrigida": f.fixed_version,
            "local": f.location,
            "descricao_scanner": (f.description or "")[:1500],
            "scanners": f.sources,
            "explorada_ativamente_kev": kb["kev"],
            "exploit_publico": kb["public_exploit"],
        },
        "ativo": {
            "nome": asset.name,
            "tipo": asset.asset_type,
            "ambiente": asset.environment,
            "exposto_internet": asset.internet_exposed,
            "criticidade_negocio": asset.business_criticality,
            "classificacao_dados": asset.data_classification,
            "descricao": asset.description,
        },
        "priorizacao": {
            "score": f.risk_score,
            "prioridade": f.priority,
            "fatores": f.risk_factors,
            "em_caminho_de_ataque": f.on_attack_path,
        },
        "conhecimento_recuperado": {
            "cwe_nome": kb["cwe_name"],
            "owasp_top10": kb["owasp"],
            "mitre_attack": kb["mitre_attack"],
            "resumo": kb["summary"],
            "impacto": kb["impact"],
            "remediacao_referencia": kb["remediation"],
            "exemplo_seguro_referencia": kb["secure_example"],
        },
        "_kb": kb,
    }


# ---------------------------------------------------------------- LLMs
def _call_openai(messages: list[dict]) -> str:
    resp = httpx.post(
        f"{settings.openai_base_url.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {settings.openai_api_key}"},
        json={
            "model": settings.openai_model,
            "messages": messages,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        },
        timeout=settings.ai_timeout_seconds,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _call_ollama(messages: list[dict]) -> str:
    resp = httpx.post(
        f"{settings.ollama_url.rstrip('/')}/api/chat",
        json={"model": settings.ollama_model, "messages": messages, "stream": False, "format": "json",
              "options": {"temperature": 0.2}},
        timeout=settings.ai_timeout_seconds,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _ask_llm(provider: str, user_payload: dict, instruction: str) -> dict:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": instruction + "\n\nCONTEXTO:\n" + json.dumps(user_payload, ensure_ascii=False, default=str)},
    ]
    raw = _call_openai(messages) if provider == "openai" else _call_ollama(messages)
    return json.loads(raw)


# ---------------------------------------------------------------- explicação
def _offline_explanation(f: Finding, asset: Asset, ctx: dict) -> dict:
    kb = ctx["_kb"]
    exposure = (
        "está exposto diretamente à internet" if asset.internet_exposed
        else "fica na rede interna" + (", mas é alcançável a partir de um sistema exposto" if any(
            fac["label"] == "Exposição" and fac["points"] > 0 for fac in f.risk_factors) else "")
    )
    exploit = (
        "Ela consta no catálogo CISA KEV, ou seja, já é explorada ativamente por atacantes."
        if kb["kev"] else "Existe exploit público disponível, o que reduz o esforço do atacante."
        if kb["public_exploit"] else "Não há exploit público conhecido no momento."
    )
    why = (
        f"O ativo {asset.name} ({asset.asset_type} em {ENV_LABEL.get(asset.environment, asset.environment)}, "
        f"criticidade {asset.business_criticality}/5, dados {DATA_LABEL.get(asset.data_classification, asset.data_classification)}) "
        f"{exposure}. {exploit} "
        f"O NEXUS calculou score {f.risk_score} ({f.priority})."
    )
    if f.on_attack_path:
        why += " Esta falha faz parte de um caminho de ataque até um sistema crítico."
    if f.corroborated:
        why += " Foi confirmada tanto na análise de código (SAST) quanto no teste dinâmico (DAST)."

    steps = list(kb["remediation"])
    example = kb["secure_example"]
    patch = suggested_patch(f)
    if patch:
        steps = [patch["summary"] + "."] + [s for s in steps if not s.startswith("Atualizar")]
        example = {"language": patch["language"], "code": patch["code"]}

    tech = kb["mitre_attack"][0]
    scenario = (
        f"Um atacante usaria a técnica {tech['id']} ({tech['name']}) contra {asset.name}"
        + (f", explorando {f.vuln_id}" if f.vuln_id.startswith("CVE-") else f" em {f.location}")
        + f". {kb['impact']}"
    )
    effort = "baixo: atualização de dependência com versão corrigida disponível" if patch else (
        "médio: requer alteração de código e novo teste" if f.category == "SAST" else
        "baixo a médio: ajuste de configuração ou código no endpoint afetado"
    )
    return {
        "o_que_e": f"{kb['cwe_name']} ({kb['cwe']}). {kb['summary']}",
        "por_que_perigoso": why,
        "cenario_ataque": scenario,
        "como_corrigir": steps,
        "exemplo_codigo": example,
        "esforco_estimado": effort,
    }


def explain_finding(f: Finding, asset: Asset) -> dict:
    ctx = build_context(f, asset)
    kb = ctx["_kb"]
    info = provider_info()
    note = ""
    body: dict | None = None
    if info["provider"] in {"openai", "ollama"}:
        try:
            payload = {k: v for k, v in ctx.items() if k != "_kb"}
            body = _ask_llm(
                info["provider"],
                payload,
                "Explique esta vulnerabilidade para o time responsável. Responda em JSON com exatamente estas chaves: "
                + json.dumps(RESPONSE_SCHEMA_HINT, ensure_ascii=False),
            )
            if not isinstance(body.get("como_corrigir"), list):
                body["como_corrigir"] = [str(body.get("como_corrigir", ""))]
            if not isinstance(body.get("exemplo_codigo"), dict):
                body["exemplo_codigo"] = {"language": "text", "code": str(body.get("exemplo_codigo", ""))}
        except Exception as exc:  # falha de rede, chave inválida, JSON malformado
            log.warning("Falha na LLM (%s): %s. Usando modo offline.", info["provider"], exc)
            note = f"A LLM ({info['provider']}) não respondeu; explicação gerada pela base de conhecimento local."
            info = {"provider": "offline", "model": "base de conhecimento local"}
            body = None
    if body is None:
        body = _offline_explanation(f, asset, ctx)

    return {
        **body,
        "patch_sugerido": suggested_patch(f),
        "referencias": {
            "cwe": kb["cwe"],
            "cwe_nome": kb["cwe_name"],
            "owasp": kb["owasp"],
            "mitre_attack": kb["mitre_attack"],
            "kev": kb["kev"],
            "exploit_publico": kb["public_exploit"],
            "links": f.references,
        },
        "provider": info["provider"],
        "model": info["model"],
        "nota": note,
        "aplicacao_automatica": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------- resumo executivo
def executive_summary(stats: dict, top: list[dict], paths: list[dict]) -> dict:
    info = provider_info()
    payload = {"indicadores": stats, "top_riscos": top, "caminhos_de_ataque": [
        {"narrativa": p["narrative"], "probabilidade": p["probability"], "alvo": p["target"]} for p in paths[:3]
    ]}
    if info["provider"] in {"openai", "ollama"}:
        try:
            body = _ask_llm(
                info["provider"],
                payload,
                "Escreva um resumo executivo para a diretoria, sem jargão. JSON com as chaves: "
                '{"titulo": "...", "situacao": "2-3 frases", "principais_riscos": ["..."], '
                '"recomendacoes": ["3 ações priorizadas"], "mensagem_final": "1 frase"}',
            )
            return {**body, **info}
        except Exception as exc:
            log.warning("Falha na LLM no resumo executivo: %s", exc)
            info = {"provider": "offline", "model": "base de conhecimento local"}

    reduction = stats.get("noise_reduction_pct", 0)
    riscos = [f"{t['priority']} · {t['title']} em {t['asset']} (score {t['risk_score']})" for t in top[:3]]
    recs = []
    if paths:
        p = paths[0]
        recs.append(f"Quebrar o caminho de ataque até {p['target']} corrigindo a falha de entrada em {p['entry']}.")
    kev_count = stats.get("kev_open", 0)
    if kev_count:
        recs.append(f"Tratar em até 48 h as {kev_count} vulnerabilidade(s) já exploradas ativamente (CISA KEV).")
    recs.append(f"Concentrar o time nas {stats.get('p1', 0)} vulnerabilidades P1 antes do restante do backlog.")
    return {
        "titulo": "Postura de segurança de aplicações",
        "situacao": (
            f"Os scanners geraram {stats.get('raw_occurrences', 0)} alertas. Após correlação, restaram "
            f"{stats.get('unique_findings', 0)} vulnerabilidades únicas e {stats.get('actionable', 0)} acionáveis "
            f"({reduction}% de redução de ruído). {stats.get('p1', 0)} exigem ação imediata."
        ),
        "principais_riscos": riscos,
        "recomendacoes": recs[:3],
        "mensagem_final": f"{len(paths)} caminho(s) de ataque viável(is) até sistemas críticos foram identificados."
        if paths else "Nenhum caminho de ataque viável até sistemas críticos no momento.",
        **info,
    }
