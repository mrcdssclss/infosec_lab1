import pytest
from src.app import create_app

@pytest.fixture
def client(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "test.db"), "JWT_SECRET": "this_is_a_very_long_dev_test_only_secret_123"})
    app.init_db()
    return app.test_client()


def register_and_login(client, username="alice", password="VeryStrong!Pass123"):
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 201
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json["access_token"]}


def test_register_and_login(client):
    register_and_login(client)


def test_no_auth_or_bad_token(client):
    assert client.get("/api/data").status_code == 401
    assert client.get("/api/data", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_invalid_password_and_weak_password(client):
    assert client.post("/auth/register", json={"username": "alice", "password": "123"}).status_code == 400
    register_and_login(client)
    assert client.post("/auth/login", json={"username": "alice", "password": "wrong"}).status_code == 401


def test_sql_injection_fails(client):
    register_and_login(client)
    bad = client.post("/auth/login", json={"username": "alice' OR 1=1 --", "password": "whatever"})
    assert bad.status_code == 401


def test_xss_escaped(client):
    token = register_and_login(client)
    res = client.post("/api/data", json={"content": '<script>alert("x")</script>'}, headers=token)
    assert res.status_code == 201
    assert res.json["content"] == '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;'
    items = client.get("/api/data", headers=token)
    assert items.status_code == 200
    assert items.json["items"][0]["content"].startswith("&lt;script&gt;")
    assert items.headers["X-Content-Type-Options"] == "nosniff"


def test_separate_users(client):
    first = register_and_login(client, "alice")
    second = register_and_login(client, "bob")
    client.post("/api/data", json={"content": "only alice"}, headers=first)
    assert client.get("/api/data", headers=second).json["items"] == []


def test_invalid_payload(client):
    token = register_and_login(client)
    assert client.post("/api/data", json={"content": ""}, headers=token).status_code == 400
    assert client.post("/api/data", json=["oops"], headers=token).status_code == 400
