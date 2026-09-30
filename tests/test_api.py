import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from datetime import datetime, timedelta

import models  # noqa: E402
from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Task 1: Share Link Tests
# ---------------------------------------------------------------------------

def test_share_scan_public():
    token = register_and_login()
    scan_resp = client.post("/scans", json={
        "title": "Public Share Finding",
        "severity": "medium",
        "affected_component": "API Gateway",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    # Generate share link without password
    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert share_resp.status_code == 200
    share_url = share_resp.json()["share_url"]
    assert "/share/" in share_url
    share_token = share_url.split("/share/")[-1]

    # Stakeholder accesses share link without authentication
    public_resp = client.get(f"/share/{share_token}")
    assert public_resp.status_code == 200
    assert public_resp.json()["id"] == scan_id
    assert public_resp.json()["title"] == "Public Share Finding"


def test_share_scan_password_protected():
    token = register_and_login()
    scan_resp = client.post("/scans", json={
        "title": "Secret Vulnerability",
        "severity": "critical",
        "affected_component": "Payment Gateway",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    # Generate share link with password
    share_resp = client.post(f"/scans/{scan_id}/share", json={
        "password": "super-secret-password-123"
    }, headers=auth_headers(token))
    assert share_resp.status_code == 200
    share_token = share_resp.json()["share_url"].split("/share/")[-1]

    # Access without password should be 401
    no_pw_resp = client.get(f"/share/{share_token}")
    assert no_pw_resp.status_code == 401
    assert "Password required" in no_pw_resp.json()["detail"]

    # Access with wrong password should be 401
    wrong_pw_resp = client.get(f"/share/{share_token}?password=wrongpassword")
    assert wrong_pw_resp.status_code == 401
    assert "Invalid password" in wrong_pw_resp.json()["detail"]

    # Access with correct password should succeed
    ok_resp = client.get(f"/share/{share_token}?password=super-secret-password-123")
    assert ok_resp.status_code == 200
    assert ok_resp.json()["id"] == scan_id
    assert ok_resp.json()["title"] == "Secret Vulnerability"


def test_share_scan_expired():
    token = register_and_login()
    scan_resp = client.post("/scans", json={
        "title": "Expiring Finding",
        "severity": "low",
        "affected_component": "Logger",
    }, headers=auth_headers(token))
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_token = share_resp.json()["share_url"].split("/share/")[-1]

    # Manually expire the token in the DB
    db = TestingSessionLocal()
    try:
        shared_record = db.query(models.SharedScan).filter(models.SharedScan.token == share_token).first()
        shared_record.expires_at = datetime.utcnow() - timedelta(hours=1)
        db.commit()
    finally:
        db.close()

    # Expired token access should return 404
    resp = client.get(f"/share/{share_token}")
    assert resp.status_code == 404


def test_share_scan_idor_prevention():
    # Alice creates a scan
    alice_token = register_and_login(username="alice_share", email="alice_share@example.com")
    scan_resp = client.post("/scans", json={
        "title": "Alice Scan",
        "severity": "high",
        "affected_component": "Core",
    }, headers=auth_headers(alice_token))
    alice_scan_id = scan_resp.json()["id"]

    # Bob tries to share Alice's scan
    bob_token = register_and_login(username="bob_share", email="bob_share@example.com")
    share_resp = client.post(f"/scans/{alice_scan_id}/share", json={}, headers=auth_headers(bob_token))
    assert share_resp.status_code == 404


def test_share_nonexistent_scan():
    token = register_and_login()
    resp = client.post("/scans/99999/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 404


def test_get_nonexistent_share_token():
    resp = client.get("/share/non-existent-token-xyz")
    assert resp.status_code == 404
