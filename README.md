<!--
  SPDX-License-Identifier: BSD-3-Clause
  Copyright (c) 2026 Matheus de Alencar (RM572185)
-->
# NEXUS · Application Security Posture Management com IA

**Integrante:** Matheus de Alencar · RM572185

> O objetivo do NEXUS não é gerar mais alertas. É gerar decisões.

O NEXUS é uma camada central de inteligência sobre os scanners que a empresa já usa
(Trivy, Snyk, OWASP ZAP, SonarQube). Ele **recebe** os relatórios, **elimina duplicidades**,
**isola prováveis falsos positivos**, **mapeia caminhos de ataque** até sistemas críticos e
**prioriza pelo risco real**, não só pelo CVSS. Uma IA com RAG explica cada falha e sugere a
correção, sem aplicar nada automaticamente.

Licença: **BSD 3-Clause** — veja [LICENSE.md](LICENSE.md).

---

## Início rápido

```bash
git clone <url-do-repositorio> nexus && cd nexus
docker compose up -d --build
```

| O quê | Endereço |
|---|---|
| Dashboard | http://localhost:8080 |
| API (Swagger) | http://localhost:8000/docs |

Na primeira execução o NEXUS carrega o ambiente de demonstração **NexusBank** (5 ativos e
6 relatórios reais de scanners). Passo a passo completo, instalação sem Docker e solução de
problemas: **[docs/INSTALACAO.md](docs/INSTALACAO.md)**.

---

## Funcionalidades implementadas

| Módulo | O que faz |
|---|---|
| **Central de ingestão** | Upload pelo dashboard ou `curl` no CI/CD. Detecta o formato automaticamente e normaliza Trivy (SCA + container), Snyk (SCA), OWASP ZAP (DAST) e SonarQube (SAST) em um modelo único. |
| **Motor de correlação** | Deduplica entre scanners (o Log4Shell do Trivy e do Snyk vira uma vulnerabilidade), consolida alertas de configuração repetidos por URL, correlaciona o mesmo CVE entre aplicações e confirma falhas achadas por SAST **e** DAST. |
| **Redução de falsos positivos** | Heurísticas: código de teste, dependências só de teste, baixa confiança do DAST, achados informativos. O item fica marcado e rebaixado, e o analista decide. |
| **Attack Path Analysis** | Grafo Internet → ativos expostos → dependências → joias da coroa (bancos e dados restritos). Só considera viável o caminho em que cada salto tem uma falha explorável e calcula a probabilidade de comprometimento. |
| **Priorização contextual** | Score 0–100 com fatores explicados: CVSS, exploração ativa (CISA KEV), exploit público, exposição, criticidade de negócio, classificação dos dados, ambiente e presença em caminho de ataque. Mudou o contexto do ativo, tudo é recalculado. |
| **IA de remediação (RAG)** | Recupera CWE, OWASP Top 10, MITRE ATT&CK e KEV da base local e envia à LLM com o contexto do ativo. Responde: o que é, por que é perigosa *aqui*, cenário de ataque, como corrigir, exemplo de código seguro e patch de dependência. |
| **Resumo executivo com IA** | Texto para a diretoria com situação, principais riscos e 3 ações priorizadas. |
| **Gestão do ciclo de vida** | Triagem (aberta, em correção, corrigida, falso positivo, risco aceito), detecção automática de correção na reimportação, MTTR, histórico de risco e exportação CSV. |

### IA: três modos

| Modo | Quando usar | Configuração |
|---|---|---|
| OpenAI (GPT-4o / GPT-4.1) | Melhor qualidade de texto | `OPENAI_API_KEY` |
| Local (Llama 3 / Mistral via Ollama) | Ambientes com restrição de privacidade | `OLLAMA_URL`, `OLLAMA_MODEL` |
| Offline | Sem internet ou sem chave | nada (padrão) |

Com `AI_PROVIDER=auto` (padrão) o NEXUS usa a OpenAI se houver chave, senão o Ollama se houver
URL, senão o modo offline. Se a LLM falhar, a resposta cai para o modo offline e avisa.

---

## Como o score é calculado

```
Severidade técnica   CVSS × 4                              até 40
Explorabilidade      CISA KEV 20 | exploit público 12      até 20
Exposição            internet 20 | alcançável 10           até 20 *
Impacto no negócio   criticidade × 3 + dados (0 a 5)       até 20 *
Bônus                SAST+DAST +5 | caminho de ataque +5
Ambiente             produção ×1.0 | homologação ×0.7 | dev ×0.5
Provável FP          ×0.4

* ponderados por max(0.3, CVSS/7) quando CVSS < 7 e não há exploit
Prioridade: P1 ≥ 75 | P2 ≥ 55 | P3 ≥ 35 | P4 < 35
```

Exemplo no ambiente de demonstração: o **Text4Shell (CVSS 9.8)** em um serviço interno de
baixa criticidade fica em **P2 (58)**, enquanto o **jQuery vulnerável (CVSS 6.1, exploit
público)** no internet banking fica em **P1 (79)**. Exponha o serviço interno à internet na
tela de ativos e o Text4Shell sobe para P1 na hora.

---

## Arquitetura

```
 Scanners / CI-CD ──► Central de ingestão ──► Motor de correlação ──► Attack Path ──► Priorização
 (Trivy, Snyk,         parsers + detecção     dedup, FP, SAST+DAST     grafo de        score
  ZAP, SonarQube)      de formato                                      ataque          contextual
                                                       │                                   │
                                                       ▼                                   ▼
                                                  PostgreSQL ◄──────────────── IA (RAG) ── Dashboard React
```

| Camada | Tecnologia |
|---|---|
| Backend | Python 3.12, FastAPI, SQLAlchemy 2 |
| Banco | PostgreSQL 16 (SQLite para desenvolvimento local) |
| Frontend | React 19, Vite, Tailwind CSS 4 |
| IA | OpenAI GPT-4o / Ollama (Llama 3, Mistral) / offline, com RAG sobre CVE, OWASP, ATT&CK e CWE |
| Infra | Docker, Docker Compose, Kubernetes (`k8s/nexus.yaml`) |

### Estrutura do repositório

```
backend/
  app/
    parsers/        Trivy, Snyk, ZAP, SonarQube → formato normalizado
    services/       correlation, scoring, attack_graph, ai (RAG), pipeline
    routers/        API REST
    knowledge/      base de conhecimento (CWE↔OWASP↔ATT&CK) e inteligência de ameaças (KEV)
  samples/          relatórios reais de exemplo para testar a ingestão
  tests/            25 testes automatizados (pytest)
frontend/
  src/pages/        Visão executiva, Vulnerabilidades, Caminhos de ataque, Ativos, Ingestão
docs/               instalação, roteiro do vídeo, capturas de tela
k8s/                manifesto Kubernetes
```

---

## API principal

| Método | Rota | Descrição |
|---|---|---|
| POST | `/api/imports` | Envia relatório (`file`, `asset_id`, `scanner` opcional) |
| GET | `/api/findings` | Lista priorizada com filtros (`priority`, `category`, `asset_id`, `status`, `q`) |
| POST | `/api/findings/{id}/explain` | Explicação e remediação por IA |
| PATCH | `/api/findings/{id}` | Triagem (`status`) |
| GET | `/api/findings/export.csv` | Exportação |
| GET | `/api/attack-paths` | Grafo e caminhos de ataque |
| GET | `/api/dashboard` | Indicadores executivos |
| POST | `/api/ai/executive-summary` | Resumo executivo |
| GET/POST/PATCH | `/api/assets` | Ativos e contexto de negócio |
| GET/POST/DELETE | `/api/dependencies` | Arestas do grafo |
| POST | `/api/demo/reset` | Restaura a demonstração |

Exemplo de integração no pipeline:

```bash
trivy image -f json -o trivy.json registry.empresa.com/api-pagamentos:2.4.1
curl -F "file=@trivy.json" -F "asset_id=2" http://nexus.empresa.com:8000/api/imports
```

---

## Testes

```bash
cd backend
pip install -r requirements-dev.txt
pytest -q
```

Os testes cobrem os quatro parsers, deduplicação entre scanners, priorização contextual,
caminhos de ataque, correlação SAST+DAST, falsos positivos, recálculo por mudança de contexto,
detecção de correção, upload, IA offline, IA com LLM simulada e queda para offline.

---

## Licença

Copyright (c) 2026, Equipe NEXUS. Distribuído sob a licença BSD 3-Clause.
Texto completo em [LICENSE.md](LICENSE.md).
