import pytest
from fastapi.testclient import TestClient

from app.db.session import get_db
from app.main import app


PASSWORD = "SYNTHETIC_PASSWORD_MARKER"
DSN = f"postgresql://demo:{PASSWORD}@invalid.example/demo"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_db, lambda: None)
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("payload,location", [
    ({"dsn": DSN}, ["body", "name"]),
    ({"name": "demo", "dsn": {"password": PASSWORD}}, ["body", "dsn"]),
    ([{"name": "demo", "dsn": DSN}], ["body"]),
])
def test_invalid_registration_does_not_echo_credentials(client, caplog, payload, location):
    response = client.post("/sources", json=payload)
    assert response.status_code == 422
    assert PASSWORD not in response.text
    assert DSN not in response.text
    assert PASSWORD not in caplog.text
    errors = response.json()["detail"]
    assert any(error["loc"] == location for error in errors)
    assert all(set(error) == {"type", "loc", "msg"} for error in errors)


def test_malformed_json_does_not_echo_credentials(client, caplog):
    response = client.post(
        "/sources", content=f'{{"dsn":"{DSN}", broken}}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert PASSWORD not in response.text
    assert PASSWORD not in caplog.text
    assert response.json()["detail"][0]["type"] == "json_invalid"


def test_invalid_path_keeps_validation_location(client):
    response = client.get("/sources/not-an-integer/inventory")
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["path", "source_id"]
