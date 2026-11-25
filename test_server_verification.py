import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

# Ensure backend directory is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import database
import models  # noqa: F401 - ensures all ORM tables are registered on Base.metadata
from database import Base, get_db
from main import app

# Isolated in-memory SQLite database so tests never touch your dev/prod database
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def _build_mock_async_client():
    """Mocks outbound OSINT HTTP requests so /api/lookup tests run offline."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 60}},
            "abuseConfidenceScore": 85,
        },
        "query_status": "no_results",
        "response": {"Attribute": []},
    }

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    return mock_client


def test_threatmapper_verification_suite():
    print("=" * 64)
    print("STARTING THREATMAPPER API, SECURITY & TENANT VERIFICATION SUITE")
    print("=" * 64)

    # Reset schema cleanly for every test run
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db

    try:
        with patch.object(database, "SessionLocal", TestingSessionLocal):
            client = TestClient(app)

            # 1. Health Check
            print("\n[1] Testing Health Check (/api/health)...")
            res = client.get("/api/health")
            assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
            print(f" -> OK: {res.json()}")

            # 2. Create Organizations
            print("\n[2] Creating Test Organizations...")
            res = client.post("/api/organizations", json={"name": "CyberCorp Security"})
            assert res.status_code == 200, f"Failed to create org 1: {res.text}"
            org1_id = res.json()["org_id"]

            res = client.post("/api/organizations", json={"name": "RivalCorp IT"})
            assert res.status_code == 200, f"Failed to create org 2: {res.text}"
            org2_id = res.json()["org_id"]
            print(f" -> Created Org 1 (ID: {org1_id}) and Org 2 (ID: {org2_id})")

            # 3. User Registration & Login (Org 1)
            print("\n[3] Testing Registration & Login...")
            res = client.post(
                "/api/auth/register",
                json={
                    "username": "alice_analyst",
                    "password": "SuperSecretPassword123!",
                    "org_id": org1_id,
                    "email": "alice@cybercorp.com",
                    "role": "analyst",
                },
            )
            assert res.status_code == 200, f"Registration failed: {res.text}"

            res = client.post(
                "/api/auth/login",
                json={"username": "alice_analyst", "password": "SuperSecretPassword123!"},
            )
            assert res.status_code == 200, f"Login failed: {res.text}"
            token_org1 = res.json()["access_token"]
            headers_org1 = {"Authorization": f"Bearer {token_org1}"}

            # Reject bad password
            bad_login = client.post(
                "/api/auth/login",
                json={"username": "alice_analyst", "password": "WrongPassword!"},
            )
            assert bad_login.status_code == 401
            print(" -> Registration, valid login (200), and invalid password rejection (401) verified.")

            # 4. Profile & Unauthenticated Rejection
            print("\n[4] Testing /api/auth/me and Unauthenticated Rejection...")
            res = client.get("/api/auth/me", headers=headers_org1)
            assert res.status_code == 200
            assert res.json()["org_id"] == org1_id

            unauth = client.get(f"/api/organizations/{org1_id}/watchlist")
            assert unauth.status_code == 401
            print(" -> Profile verified and unauthenticated route blocked with 401.")

            # 5. Pre-Flight Validation & Mocked IOC Lookup (/api/lookup)
            print("\n[5] Testing Pre-Flight Input Validation & IOC Lookup...")
            invalid_lookup = client.post(
                "/api/lookup",
                json={"ioc_value": "not_a_valid_ip_or_hash", "ioc_type": "ip"},
                headers=headers_org1,
            )
            assert invalid_lookup.status_code == 400, (
                f"Expected 400 for invalid IOC, got {invalid_lookup.status_code}"
            )
            print(" -> Pre-flight validation rejected malformed IOC with 400 Bad Request.")

            with patch("httpx.AsyncClient", return_value=_build_mock_async_client()):
                valid_lookup = client.post(
                    "/api/lookup",
                    json={"ioc_value": "185.220.101.5", "ioc_type": "ip"},
                    headers=headers_org1,
                )
                assert valid_lookup.status_code == 200, f"Lookup failed: {valid_lookup.text}"
                lookup_data = valid_lookup.json()
                assert "confidence_score" in lookup_data and "verdict" in lookup_data
                print(
                    f" -> Lookup succeeded: verdict={lookup_data['verdict']}, "
                    f"score={lookup_data['confidence_score']}"
                )

            # 6. Watchlist Management (Org 1)
            print("\n[6] Testing Watchlist Addition & Retrieval...")
            res = client.post(
                "/api/watchlist",
                json={"org_id": org1_id, "ioc_value": "185.220.101.5", "ioc_type": "ip"},
                headers=headers_org1,
            )
            assert res.status_code == 200, f"Watchlist add failed: {res.text}"
            watchlist_id = res.json().get("watchlist_id")

            res = client.get(f"/api/organizations/{org1_id}/watchlist", headers=headers_org1)
            assert res.status_code == 200
            assert len(res.json()["watchlist"]) == 1
            print(f" -> Added and retrieved watchlist item (ID: {watchlist_id}).")

            # 7. Multi-Tenant Isolation (Org 2 Blocked from Org 1)
            print("\n[7] Testing Cross-Tenant Isolation (Org 2 vs Org 1)...")
            res = client.post(
                "/api/auth/register",
                json={
                    "username": "bob_competitor",
                    "password": "Password456!",
                    "org_id": org2_id,
                    "email": "bob@rivalcorp.com",
                    "role": "analyst",
                },
            )
            assert res.status_code == 200
            headers_org2 = {"Authorization": f"Bearer {res.json()['access_token']}"}

            assert (
                client.get(
                    f"/api/organizations/{org1_id}/watchlist", headers=headers_org2
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/watchlist",
                    json={"org_id": org1_id, "ioc_value": "1.1.1.1", "ioc_type": "ip"},
                    headers=headers_org2,
                ).status_code
                == 403
            )
            print(" -> Cross-tenant read and write blocked with 403 Forbidden.")

            # 8. SIEM Config & STIX 2.1 Export
            print("\n[8] Testing SIEM Config & STIX 2.1 Export...")
            res = client.post(
                f"/api/organizations/{org1_id}/siem/config",
                json={
                    "siem_type": "splunk",
                    "endpoint_url": "https://splunk.cybercorp.com:8088/services/collector/raw",
                    "auth_token": "cybercorp-secret-token-12345",
                    "sync_mode": "push",
                },
                headers=headers_org1,
            )
            assert res.status_code == 200
            assert (
                client.get(
                    f"/api/organizations/{org1_id}/siem/config", headers=headers_org2
                ).status_code
                == 403
            )

            if watchlist_id:
                stix_res = client.get(
                    f"/api/export/stix21/{watchlist_id}", headers=headers_org1
                )
                assert stix_res.status_code == 200
                stix = stix_res.json()
                assert stix["type"] == "bundle"
                assert stix["objects"][0]["type"] == "indicator"
                assert (
                    client.get(
                        f"/api/export/stix21/{watchlist_id}", headers=headers_org2
                    ).status_code
                    == 403
                )
            print(" -> SIEM config and STIX 2.1 bundle export verified with 403 tenant guards.")

            # 9. Dashboard Correlation, Alerts & Wazuh Feed Endpoints
            print("\n[9] Testing /api/correlation, /api/alerts, and /api/feed...")
            corr = client.get("/api/correlation", headers=headers_org1)
            assert corr.status_code == 200, f"Correlation failed: {corr.text}"

            alerts = client.get("/api/alerts", headers=headers_org1)
            assert alerts.status_code == 200, f"Alerts failed: {alerts.text}"
            assert alerts.json()["org_id"] == org1_id

            feed_org2 = client.get("/api/feed", headers=headers_org2)
            assert feed_org2.status_code == 200
            assert len(feed_org2.json().get("indicators", feed_org2.json().get("feed", []))) == 0
            print(" -> Correlation, alerts, and tenant-scoped Wazuh feed verified.")

        print("\n" + "=" * 64)
        print("ALL API, SECURITY & MULTI-TENANT TESTS PASSED!")
        print("=" * 64)
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=test_engine)


if __name__ == "__main__":
    test_threatmapper_verification_suite()