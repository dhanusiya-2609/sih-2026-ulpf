import os
import sys
import tempfile
import shutil

import pytest

# Ensure env vars are set BEFORE app modules are imported anywhere.
_tmp_dir = tempfile.mkdtemp(prefix="ulpf_test_")
os.environ["ULPF_DATA_DIR"] = _tmp_dir
os.environ["ULPF_DATABASE_URL"] = f"sqlite:///{_tmp_dir}/test.db"
os.environ["ULPF_ENABLE_UDP"] = "false"
os.environ["ULPF_ENABLE_TCP"] = "false"
os.environ["ULPF_JWT_SECRET"] = "test-secret"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="session", autouse=True)
def _cleanup_tmp():
    yield
    shutil.rmtree(_tmp_dir, ignore_errors=True)


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth_headers(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
