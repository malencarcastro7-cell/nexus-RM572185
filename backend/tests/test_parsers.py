# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import json

import pytest

from app.parsers import detect_scanner, parse_report
from app.services.correlation import dedup_key, false_positive_reason

from .conftest import SAMPLES


def load(name):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "filename,scanner",
    [
        ("trivy-api-pagamentos-v2.4.1.json", "trivy"),
        ("snyk-api-pagamentos.json", "snyk"),
        ("zap-portal-clientes.json", "zap"),
        ("sonarqube-portal-clientes.json", "sonarqube"),
    ],
)
def test_detecta_formato(filename, scanner):
    assert detect_scanner(load(filename)) == scanner


def test_formato_desconhecido():
    with pytest.raises(ValueError):
        parse_report({"foo": "bar"})


def test_trivy_normaliza_cvss_e_categoria():
    _, items = parse_report(load("trivy-api-pagamentos-v2.4.1.json"))
    log4j = next(i for i in items if i.vuln_id == "CVE-2021-44228")
    assert log4j.cvss == 10.0 and log4j.severity == "critical" and log4j.category == "SCA"
    glibc = next(i for i in items if i.vuln_id == "CVE-2023-4911")
    assert glibc.category == "CONTAINER"


def test_trivy_e_snyk_geram_mesma_chave():
    _, trivy = parse_report(load("trivy-api-pagamentos-v2.4.1.json"))
    _, snyk = parse_report(load("snyk-api-pagamentos.json"))
    k1 = {dedup_key(i) for i in trivy if i.vuln_id == "CVE-2021-44228"}
    k2 = {dedup_key(i) for i in snyk if i.vuln_id == "CVE-2021-44228"}
    assert k1 == k2 and len(k1) == 1


def test_zap_consolida_cabecalho_ausente_no_site():
    _, items = parse_report(load("zap-portal-clientes.json"))
    csp = [i for i in items if i.cwe == "CWE-693" and "Content Security" in i.title]
    assert len(csp) == 5
    assert len({dedup_key(i) for i in csp}) == 1


def test_zap_extrai_cve_de_biblioteca_js():
    _, items = parse_report(load("zap-portal-clientes.json"))
    jq = next(i for i in items if i.title == "Vulnerable JS Library")
    assert jq.vuln_id == "CVE-2020-11022" and jq.exploit_public


def test_sonarqube_mapeia_cwe_e_caminho():
    _, items = parse_report(load("sonarqube-portal-clientes.json"))
    sqli = next(i for i in items if i.vuln_id.endswith("S3649"))
    assert sqli.cwe == "CWE-89"
    assert sqli.location.startswith("src/main/java/")


def test_heuristicas_de_falso_positivo():
    _, sonar = parse_report(load("sonarqube-portal-clientes.json"))
    test_cred = next(i for i in sonar if i.vuln_id.endswith("S2068"))
    assert "teste" in false_positive_reason(test_cred)
    _, snyk = parse_report(load("snyk-api-pagamentos.json"))
    junit = next(i for i in snyk if i.package == "junit:junit")
    assert false_positive_reason(junit)
