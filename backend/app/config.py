# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
"""Configuração da aplicação lida de variáveis de ambiente."""

import os
from dataclasses import dataclass, field


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "sim", "on"}


@dataclass(frozen=True)
class Settings:
    # Banco de dados: PostgreSQL em produção; SQLite como fallback para desenvolvimento local.
    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./nexus.db")
    )

    # Provedor de IA: "openai", "ollama" (Llama 3 / Mistral locais) ou "offline".
    # Em "auto", usa OpenAI se houver chave, senão Ollama se houver URL, senão offline.
    ai_provider: str = field(default_factory=lambda: os.getenv("AI_PROVIDER", "auto").lower())
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openai_model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o"))
    openai_base_url: str = field(
        default_factory=lambda: os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    )
    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_URL", ""))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3"))
    ai_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("AI_TIMEOUT_SECONDS", "60"))
    )

    # Carrega ativos e relatórios de exemplo na primeira inicialização.
    seed_demo: bool = field(default_factory=lambda: _bool(os.getenv("SEED_DEMO"), True))

    cors_origins: list[str] = field(
        default_factory=lambda: [
            o.strip()
            for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8080").split(",")
            if o.strip()
        ]
    )


settings = Settings()
