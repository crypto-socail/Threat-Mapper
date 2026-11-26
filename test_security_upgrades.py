import os
import sys
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import database
import models  # noqa: F401
from auth import decrypt_secret
from database import Base, get_db
from engine import evaluate_sources
from main import app

test_engine = create_engine(
    "sqlite:///:memory:",
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


def test_security_and_scoring_upgrades():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db

    try:
        client = TestClient(app)
        suffix = uuid4().hex[:6]

        # 1. Create test organization
        org_resp = client.post("/api/organizations", json={"name": f"SecoraTest-{suffix}"})
        assert org_resp.status_code == 200
        org_id = org_resp.json()["org_id"]

        # 2. Privilege escalation block (role='superadmin' must be forced to 'analyst')
        reg_resp = client.post(
            "/api/auth/register",
            json={
                "username": f"analyst_{suffix}",
                "password": "StrongPassword123!",
                "org_id": org_id,
                "role": "superadmin",
            },
        )
        assert reg_resp.status_code == 200
        reg_data = reg_resp.json()
        assert reg_data["role"] == "analyst", f"Privilege escalation! Got role: {reg_data['role']}"
        headers = {"Authorization": f"Bearer {reg_data['access_token']}"}

        # 3. SSRF protection blocks internal/loopback/metadata SIEM URLs
        for unsafe_url in [
            "http://127.0.0.1:8088/services/collector",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:9200",
        ]:
            ssrf_resp = client.post(
                f"/api/organizations/{org_id}/siem/config",
                headers=headers,
                json={
                    "siem_type": "splunk",
                    "endpoint_url": unsafe_url,
                    "auth_token": "secret-token",
                    "sync_mode": "push",
                },
            )
            assert ssrf_resp.status_code in (400, 422), f"SSRF URL was not blocked: {unsafe_url}"

        # 4. Valid SIEM config encrypts auth_token at rest
        raw_token = "hec-token-99887766"
        valid_siem = client.post(
            f"/api/organizations/{org_id}/siem/config",
            headers=headers,
            json={
                "siem_type": "splunk",
                "endpoint_url": "https://splunk.example.com:8088/services/collector",
                "auth_token": raw_token,
                "sync_mode": "push",
            },
        )
        assert valid_siem.status_code == 200

        db = TestingSessionLocal()
        try:
            stored = (
                db.query(models.SiemConfigRecord)
                .filter(models.SiemConfigRecord.org_id == org_id)
                .first()
            )
            assert stored is not None
            assert stored.auth_token != raw_token, "SIEM token was stored in plaintext!"
            assert decrypt_secret(stored.auth_token) == raw_token
        finally:
            db.close()

        # 5. Scoring denominator fixes (applicable sources only + rate-limit resilience)
        domain_score, domain_verdict, evaluated, _ = evaluate_sources({
            "virustotal": {"is_flagged": False, "applicable": False},
            "abuseipdb": {"is_flagged": False, "applicable": False},
            "urlhaus": {"is_flagged": True, "applicable": True},
            "misp": {"is_flagged": False, "applicable": False},
            "hibp": {"is_flagged": False, "applicable": False},
        })
        assert domain_score == 100.0
        assert domain_verdict == "malicious"
        assert evaluated == ["urlhaus"]

        ratelimit_score, ratelimit_verdict, _, warnings = evaluate_sources({
            "virustotal": {"is_flagged": False, "applicable": True, "error": "QuotaExceeded"},
            "abuseipdb": {"is_flagged": True, "applicable": True},
            "urlhaus": {"is_flagged": False, "applicable": False},
            "misp": {"is_flagged": False, "applicable": False},
            "hibp": {"is_flagged": False, "applicable": False},
        })
        assert ratelimit_score == 100.0
        assert ratelimit_verdict == "malicious"
        assert "virustotal: QuotaExceeded" in warnings

        # 6. Watchlist validation, STIX 2.1 export, CSV export, and DELETE
        bad_watch = client.post(
            "/api/watchlist",
            headers=headers,
            json={"org_id": org_id, "ioc_value": "999.999.999.999", "ioc_type": "ip"},
        )
        assert bad_watch.status_code == 400

        good_watch = client.post(
            "/api/watchlist",
            headers=headers,
            json={"org_id": org_id, "ioc_value": "185.220.101.1", "ioc_type": "ip"},
        )
        assert good_watch.status_code == 200
        watch_id = good_watch.json()["watchlist_id"]

        stix_resp = client.get(f"/api/export/stix21/{watch_id}", headers=headers)
        assert stix_resp.status_code == 200
        assert stix_resp.json()["objects"][0]["pattern"] == "[ipv4-addr:value = '185.220.101.1']"

        csv_resp = client.get("/api/export/csv", headers=headers)
        assert csv_resp.status_code == 200
        assert "185.220.101.1" in csv_resp.text

        del_resp = client.delete(f"/api/watchlist/{watch_id}", headers=headers)
        assert del_resp.status_code == 200

        # 7. Alert listing & acknowledgment endpoint
        db = TestingSessionLocal()
        try:
            alert = models.AlertRecord(
                org_id=org_id,
                ioc_value="185.220.101.1",
                ioc_type="ip",
                threat_score=88.5,
                message="Test escalation alert",
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            alert_id = alert.id
        finally:
            db.close()

        alerts_resp = client.get("/api/alerts", headers=headers)
        assert alerts_resp.status_code == 200
        assert alerts_resp.json()["alerts"][0]["acknowledged"] is False

        ack_resp = client.patch(f"/api/alerts/{alert_id}/acknowledge", headers=headers)
        assert ack_resp.status_code == 200
        assert ack_resp.json()["acknowledged"] is True
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=test_engine)