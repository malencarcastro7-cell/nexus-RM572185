<!--
  SPDX-License-Identifier: BSD-3-Clause
  Copyright (c) 2026 Equipe NEXUS
-->
# Guia de instalação do NEXUS em uma infraestrutura nova

Este guia leva o NEXUS de uma máquina vazia até o dashboard funcionando com dados de
demonstração. Há três caminhos:

- **A. Docker Compose** (recomendado, ~5 minutos)
- **B. Instalação manual** sem Docker (desenvolvimento)
- **C. Kubernetes** (produção)

---

## Requisitos

| Recurso | Mínimo |
|---|---|
| CPU / memória | 2 vCPU, 4 GB de RAM |
| Disco | 5 GB livres |
| Sistema | Linux (Ubuntu 22.04+), Windows 10/11 com WSL2 ou macOS |
| Portas livres | 8080 (dashboard) e 8000 (API) |
| Internet | Só para baixar imagens e dependências. A IA funciona offline. |

---

## A. Docker Compose (recomendado)

### 1. Instalar o Docker

**Ubuntu (VM ou servidor novo):**

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
docker --version && docker compose version
```

**Windows / macOS:** instale o [Docker Desktop](https://www.docker.com/products/docker-desktop/)
e abra-o antes de continuar. No Windows, use o terminal do WSL2 ou o PowerShell.

### 2. Obter o código

```bash
git clone <url-do-repositorio> nexus
cd nexus
```

Ou descompacte o `nexus.zip` e entre na pasta `nexus`.

### 3. Configurar (opcional)

```bash
cp .env.example .env
```

Edite o `.env` se quiser:

- trocar a senha do banco (`POSTGRES_PASSWORD`);
- usar a OpenAI: preencha `OPENAI_API_KEY` (modelo padrão `gpt-4o`);
- usar um modelo local: preencha `OLLAMA_URL` (ex.: `http://host.docker.internal:11434`) e `OLLAMA_MODEL` (`llama3` ou `mistral`).

Sem `.env`, tudo funciona com a IA no modo offline (base de conhecimento local).

### 4. Subir

```bash
docker compose up -d --build
```

O primeiro build leva de 2 a 5 minutos. Acompanhe:

```bash
docker compose ps          # os 3 serviços devem ficar "running"/"healthy"
docker compose logs -f backend
```

Quando aparecer `Ambiente de demonstração carregado (NexusBank)`, está pronto.

### 5. Acessar

| O quê | Endereço |
|---|---|
| Dashboard | http://localhost:8080 |
| Documentação da API | http://localhost:8000/docs |
| Health check | http://localhost:8000/api/health |

### 6. Parar, atualizar e limpar

```bash
docker compose down             # para (mantém os dados)
docker compose up -d --build    # atualiza após mudanças no código
docker compose down -v          # para e apaga o banco
```

---

## B. Instalação manual (sem Docker)

Requisitos: **Python 3.11+** e **Node.js 20+**. O banco padrão é SQLite (arquivo local);
para PostgreSQL defina `DATABASE_URL`.

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Com PostgreSQL:

```bash
export DATABASE_URL="postgresql+psycopg://usuario:senha@localhost:5432/nexus"
```

Com OpenAI:

```bash
export OPENAI_API_KEY="sk-..."
```

### Frontend (em outro terminal)

```bash
cd frontend
npm install
npm run dev
```

Acesse http://localhost:5173. O Vite encaminha `/api` para `http://localhost:8000`.

### Testes automatizados

```bash
cd backend
pip install -r requirements-dev.txt
pytest -q          # 25 testes
```

---

## C. Kubernetes

```bash
docker build -t <registry>/nexus-backend:1.0.0 backend
docker build -t <registry>/nexus-frontend:1.0.0 frontend
docker push <registry>/nexus-backend:1.0.0
docker push <registry>/nexus-frontend:1.0.0

# troque <registry> e as senhas em k8s/nexus.yaml
kubectl apply -f k8s/nexus.yaml
kubectl -n nexus get pods
kubectl -n nexus port-forward svc/frontend 8080:80
```

---

## Validar a instalação

Siga esta lista depois de subir. Cada item mostra uma funcionalidade de ASPM com IA.

1. **Visão executiva** (`/`): devem aparecer 53 alertas brutos, 28 vulnerabilidades únicas, 24 acionáveis e 7 P1.
2. **Resumo executivo com IA**: clique no botão roxo; a IA gera situação, riscos e recomendações.
3. **Vulnerabilidades**: o primeiro item é o Log4Shell em `api-pagamentos`, com as marcas KEV, Caminho de ataque e 2 scanners (Trivy + Snyk deduplicados).
4. Clique nele e em **Explicar com IA**: aparecem o que é, por que é perigosa, como corrigir, o patch do `pom.xml` e as referências OWASP / ATT&CK / CWE.
5. **Caminhos de ataque**: o caminho Internet → portal-clientes → api-pagamentos → db-transacoes aparece destacado com 63% de probabilidade.
6. **Ativos**: marque `servico-relatorios` como "Exposto à internet". Volte em Vulnerabilidades: o Text4Shell sobe de P2 para P1 e surge um segundo caminho de ataque. Desmarque para voltar.
7. **Ingestão**: envie `backend/samples/trivy-servico-relatorios.json` para o ativo `intranet-rh` e veja o resultado da correlação.
8. Para recomeçar do zero: **Ingestão → Restaurar demonstração**.

### Testar pela linha de comando

```bash
curl http://localhost:8000/api/health
curl -F "file=@backend/samples/zap-portal-clientes.json" -F "asset_id=1" http://localhost:8000/api/imports
curl "http://localhost:8000/api/findings?priority=P1" | python3 -m json.tool | head -40
curl -X POST http://localhost:8000/api/findings/1/explain | python3 -m json.tool
```

---

## Relatórios de exemplo

Em `backend/samples/`:

| Arquivo | Scanner | Ativo sugerido |
|---|---|---|
| `sonarqube-portal-clientes.json` | SonarQube (SAST) | portal-clientes |
| `zap-portal-clientes.json` | OWASP ZAP (DAST) | portal-clientes |
| `trivy-api-pagamentos-v2.3.0.json` | Trivy (SCA + container) | api-pagamentos |
| `snyk-api-pagamentos.json` | Snyk (SCA) | api-pagamentos |
| `trivy-api-pagamentos-v2.4.1.json` | Trivy, versão nova (corrige 1 CVE) | api-pagamentos |
| `trivy-servico-relatorios.json` | Trivy | servico-relatorios |

Para gerar relatórios reais dos seus projetos:

```bash
trivy image -f json -o trivy.json <imagem>
snyk test --json > snyk.json
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://seu-site -J zap.json
curl -u <token>: "https://sonar/api/issues/search?types=VULNERABILITY&componentKeys=<projeto>" > sonar.json
```

---

## Solução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| `port is already allocated` | 8080 ou 8000 em uso | Pare o outro serviço ou troque a porta em `docker-compose.yml` (ex.: `"8081:80"`) |
| Dashboard abre, mas sem dados | Backend ainda iniciando | `docker compose logs backend` e aguarde o health check |
| `permission denied` no Docker (Linux) | Usuário fora do grupo docker | `sudo usermod -aG docker $USER` e abra um novo terminal |
| IA responde "base de conhecimento local" | Sem chave configurada | Preencha `OPENAI_API_KEY` no `.env` e rode `docker compose up -d` |
| Aviso "A LLM não respondeu" | Chave inválida, sem internet ou Ollama fora do ar | Confira a chave/URL; enquanto isso a resposta usa o modo offline |
| Upload retorna "Formato não reconhecido" | JSON de outro scanner ou formato | Use Trivy, Snyk, ZAP (JSON tradicional) ou a API de issues do SonarQube |
| Quero dados limpos, sem demonstração | — | `SEED_DEMO=false` no `.env` e `docker compose down -v && docker compose up -d` |
