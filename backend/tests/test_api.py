# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import json

from app.services import ai

from .conftest import SAMPLES


def _by(client, asset, vuln):
    for f in client.get("/api/findings?status=all&include_fp=true").json():
        if f["asset"] == asset and f["vuln_id"] == vuln:
            return f
    raise AssertionError(f"{vuln} não encontrado em {asset}")


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_deduplicacao_entre_scanners(client):
    log4j = _by(client, "api-pagamentos", "CVE-2021-44228")
    assert sorted(log4j["sources"]) == ["snyk", "trivy"]
    assert log4j["occurrence_count"] >= 4
    stats = client.get("/api/dashboard").json()["stats"]
    assert stats["raw_occurrences"] > stats["unique_findings"] > stats["actionable"]


def test_priorizacao_contextual_supera_cvss(client):
    """Exemplo do produto: CVE 9.8 interna fica abaixo de CVE 6.x pública em sistema financeiro."""
    interna = _by(client, "servico-relatorios", "CVE-2022-42889")
    publica = _by(client, "portal-clientes", "CVE-2020-11022")
    assert interna["cvss"] > publica["cvss"]
    assert publica["risk_score"] > interna["risk_score"]
    assert publica["priority"] == "P1"


def test_kev_e_caminho_de_ataque(client):
    log4j = _by(client, "api-pagamentos", "CVE-2021-44228")
    assert log4j["exploit_known"] and log4j["on_attack_path"] and log4j["priority"] == "P1"
    paths = client.get("/api/attack-paths").json()["paths"]
    assert paths and paths[0]["target"] == "db-transacoes"
    assert [s["asset_name"] for s in paths[0]["steps"]] == ["portal-clientes", "api-pagamentos", "db-transacoes"]


def test_correlacao_sast_dast(client):
    assert _by(client, "portal-clientes", "javasecurity:S3649")["corroborated"]
    assert _by(client, "portal-clientes", "ZAP-40018")["corroborated"]


def test_falso_positivo_rebaixado(client):
    cred = _by(client, "portal-clientes", "java:S2068")
    assert cred["fp_suspected"] and cred["priority"] == "P4"
    ids = {f["id"] for f in client.get("/api/findings").json()}
    assert cred["id"] not in ids  # fora da lista acionável por padrão


def test_mudanca_de_contexto_recalcula(client):
    text4shell = _by(client, "servico-relatorios", "CVE-2022-42889")
    assets = {a["name"]: a for a in client.get("/api/assets").json()}
    r = client.patch(f"/api/assets/{assets['servico-relatorios']['id']}", json={"internet_exposed": True})
    assert r.status_code == 200
    depois = client.get(f"/api/findings/{text4shell['id']}").json()
    assert depois["risk_score"] > text4shell["risk_score"]
    assert len(client.get("/api/attack-paths").json()["paths"]) == 2


def test_correcao_automatica_e_mttr(client):
    resolved = _by(client, "api-pagamentos", "CVE-2023-20863")
    assert resolved["status"] == "resolved"
    assert client.get("/api/dashboard").json()["stats"]["mttr_days"] > 0


def test_upload_e_triagem(client):
    assets = {a["name"]: a for a in client.get("/api/assets").json()}
    content = (SAMPLES / "trivy-servico-relatorios.json").read_bytes()
    r = client.post(
        "/api/imports",
        files={"file": ("trivy.json", content, "application/json")},
        data={"asset_id": str(assets["intranet-rh"]["id"])},
    )
    assert r.status_code == 201 and r.json()["new_findings"] == 4
    fid = _by(client, "intranet-rh", "CVE-2022-42889")["id"]
    r = client.patch(f"/api/findings/{fid}", json={"status": "resolved"})
    assert r.json()["status"] == "resolved" and r.json()["resolved_at"]


def test_upload_invalido(client):
    r = client.post("/api/imports", files={"file": ("x.json", b"nao e json")}, data={"asset_id": "1"})
    assert r.status_code == 400


def test_explicacao_ia_offline(client):
    fid = _by(client, "api-pagamentos", "CVE-2021-44228")["id"]
    e = client.post(f"/api/findings/{fid}/explain").json()
    assert e["provider"] == "offline" and e["aplicacao_automatica"] is False
    assert e["referencias"]["owasp"].startswith("A03") and e["referencias"]["kev"]
    assert "2.17.1" in e["patch_sugerido"]["code"]
    for key in ("o_que_e", "por_que_perigoso", "como_corrigir", "exemplo_codigo"):
        assert e[key]


def test_explicacao_ia_com_llm(client, monkeypatch):
    """Simula a resposta da OpenAI e verifica o contexto RAG enviado."""
    sent = {}

    def fake_openai(messages):
        sent["prompt"] = messages[1]["content"]
        return json.dumps({
            "o_que_e": "Falha de teste", "por_que_perigoso": "x", "cenario_ataque": "y",
            "como_corrigir": ["a", "b"], "exemplo_codigo": {"language": "java", "code": "ok"},
            "esforco_estimado": "baixo",
        })

    monkeypatch.setattr(ai, "active_provider", lambda: "openai")
    monkeypatch.setattr(ai, "_call_openai", fake_openai)
    fid = _by(client, "portal-clientes", "javasecurity:S3649")["id"]
    e = client.post(f"/api/findings/{fid}/explain?force=true").json()
    assert e["provider"] == "openai" and e["o_que_e"] == "Falha de teste"
    assert "A03:2021" in sent["prompt"] and "T1190" in sent["prompt"]


def test_llm_indisponivel_cai_para_offline(client, monkeypatch):
    def boom(messages):
        raise RuntimeError("sem rede")

    monkeypatch.setattr(ai, "active_provider", lambda: "openai")
    monkeypatch.setattr(ai, "_call_openai", boom)
    fid = _by(client, "portal-clientes", "javasecurity:S3649")["id"]
    e = client.post(f"/api/findings/{fid}/explain?force=true").json()
    assert e["provider"] == "offline" and e["nota"]


def test_resumo_executivo_e_csv(client):
    s = client.post("/api/ai/executive-summary").json()
    assert s["recomendacoes"] and s["situacao"]
    r = client.get("/api/findings/export.csv")
    assert r.status_code == 200 and "Prioridade;Score" in r.text
