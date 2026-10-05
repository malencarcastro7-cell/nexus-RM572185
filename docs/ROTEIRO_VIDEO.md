<!--
  SPDX-License-Identifier: BSD-3-Clause
  Copyright (c) 2026 Equipe NEXUS
-->
# Roteiro do vídeo de demonstração (até 10 minutos)

**Antes de gravar**

- Suba o ambiente (`docker compose up -d --build`) e abra http://localhost:8080.
- Em **Ingestão**, clique em **Restaurar demonstração** para começar com os números deste roteiro.
- Deixe aberta uma pasta com `backend/samples/` para o upload.
- Navegador em tela cheia, zoom 100%, notificações desligadas.
- Gravação: OBS Studio ou o gravador do Teams/Windows (Win + Alt + R).

| Tempo | Tela | O que fazer | O que falar |
|---|---|---|---|
| 0:00–0:45 | Slide de capa ou Visão executiva | Apresentar o grupo | "Empresas usam dezenas de scanners e recebem milhares de alertas repetidos. O NEXUS é uma plataforma ASPM com IA que transforma esses alertas em decisões." |
| 0:45–1:45 | **Ingestão** | Arrastar `trivy-servico-relatorios.json`, escolher o ativo `intranet-rh`, importar | "Aceitamos Trivy, Snyk, OWASP ZAP e SonarQube. O formato é detectado sozinho e tudo vira um padrão único. Também funciona por API no pipeline de CI/CD." Mostrar o card com brutos, novas e consolidadas e o histórico. |
| 1:45–3:00 | **Visão executiva** | Mostrar o funil e os KPIs | "Seis relatórios geraram 53 alertas. Depois da correlação sobram 28 vulnerabilidades únicas, 24 acionáveis e só 7 exigem ação imediata: 54,7% de redução de ruído." Apontar KEV, caminhos de ataque e MTTR de 19 dias. |
| 3:00–3:40 | Visão executiva, Top 5 | Comparar as duas listas | "À esquerda, a ordem do NEXUS. À direita, como uma ferramenta tradicional ordenaria, só pelo CVSS. O Text4Shell, CVSS 9.8, está num serviço interno de baixa criticidade e cai para P2." |
| 3:40–5:00 | **Vulnerabilidades** | Abrir o Log4Shell (1º da lista) | Mostrar as marcas KEV, Caminho de ataque e "2 scanners". "O Trivy e o Snyk reportaram a mesma falha: o NEXUS consolidou 5 ocorrências em uma." Explicar o quadro **Por que esta prioridade**, fator a fator. |
| 5:00–6:30 | Mesmo item | Clicar em **Explicar com IA** | "A IA usa RAG: busca CWE, OWASP Top 10, MITRE ATT&CK e o catálogo KEV, junta com o contexto do ativo e explica o que é, por que é perigosa aqui e como corrigir." Mostrar o patch do `pom.xml` e o aviso: "ela recomenda, mas não aplica nada; o controle fica com o time." |
| 6:30–7:00 | Vulnerabilidades | Marcar **Mostrar prováveis falsos positivos** | Mostrar a credencial em código de teste e a dependência JUnit. "Não escondemos nada: marcamos, rebaixamos e o analista decide." |
| 7:00–8:15 | **Caminhos de ataque** | Mostrar o grafo e o caminho #1 | "Um atacante na internet explora o jQuery do portal, depois o Log4Shell da API de pagamentos e chega ao banco de transações: 63% de probabilidade. Corrigir qualquer salto quebra o caminho." |
| 8:15–9:15 | **Ativos** → Vulnerabilidades → Caminhos | Em `servico-relatorios`, clicar em **Somente rede interna** para virar **Exposto à internet** | "Se esse serviço for publicado na internet, o risco muda na hora." Mostrar o Text4Shell subindo de 58 (P2) para 78 (P1) e o segundo caminho de ataque. Voltar o ativo para rede interna. |
| 9:15–9:45 | Visão executiva | **Resumo executivo com IA** | "Para a diretoria, um resumo em linguagem de negócio com as três ações prioritárias." |
| 9:45–10:00 | Qualquer tela | Encerrar | "O NEXUS não mostra apenas vulnerabilidades: mostra quais riscos importam, como podem ser explorados e como corrigir rápido. Código aberto sob licença BSD-3-Clause." |

## Vídeo de instalação (entregável 02, se optarem por vídeo)

Grave em uma VM Ubuntu limpa, seguindo `docs/INSTALACAO.md`, seção A:

1. `curl -fsSL https://get.docker.com | sudo sh`
2. `git clone <repo> nexus && cd nexus`
3. `cp .env.example .env` (mostrar onde vai a chave da OpenAI, opcional)
4. `docker compose up -d --build` e `docker compose ps`
5. Abrir http://localhost:8080 e http://localhost:8000/docs
6. Rodar os testes: `cd backend && pip install -r requirements-dev.txt && pytest -q`

Cerca de 3 a 4 minutos com cortes no tempo de build.
