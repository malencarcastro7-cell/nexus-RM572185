# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Equipe NEXUS
# NEXUS - Application Security Posture Management orientado por IA.
# Distribuído sob a licença BSD 3-Clause. Veja LICENSE.md na raiz do projeto.
import os
import sys
from pathlib import Path

import pytest

os.environ["DATABASE_URL"] = "sqlite:///./test_nexus.db"
os.environ["SEED_DEMO"] = "true"
os.environ["AI_PROVIDER"] = "offline"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import reset, seed  # noqa: E402

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture()
def client():
    with TestClient(app) as c:
        with SessionLocal() as db:
            reset(db)
            seed(db)
        yield c


def pytest_sessionfinish(session, exitstatus):
    Path("test_nexus.db").unlink(missing_ok=True)
