import sys
import uuid
import httpx

BASE_URL = "http://127.0.0.1:8000"


def run_live_smoke_test():
    run_id = uuid.uuid4().hex[:6]
    print(f"Testing live FastAPI server at {BASE_URL} (Run ID: {run_id})")

    try:
        with httpx.Client(base_url=BASE_URL, timeout=15.0) as client:
            # 1. Health & OpenAPI Schema
            r = client.get("/api/health")
            assert r.status_code == 200, f"Health check failed: {r.text}"
            print("[+] GET /api/health:", r.json())

            r = client.get("/openapi.json")
            assert r.status_code == 200, f"OpenAPI schema failed: {r.status_code}"
            print("[+] GET /openapi.json: version", r.json().get("info", {}).get("version"))

            # 2. Create Unique Organization
            org_name = f"LiveTest Sentinel Org {run_id}"
            r = client.post("/api/organizations", json={"name": org_name})
            assert r.status_code == 200, f"Org creation failed: {r.text}"
            org_id = r.json()["org_id"]
            print(f"[+] POST /api/organizations: Created '{org_name}' (ID: {org_id})")

            # 3. Register & Login User
            username = f"analyst_{run_id}"
            password = "StrongPassword123!"
            r = client.post(
                "/api/auth/register",
                json={
                    "username": username,
                    "password": password,
                    "org_id": org_id,
                    "email": f"{username}@sentinel.org",
                    "role": "analyst",
                },
            )
            assert r.status_code == 200, f"Register failed: {r.text}"

            r = client.post("/api/auth/login", json={"username": username, "password": password})
            assert r.status_code == 200, f"Login failed: {r.text}"
            token = r.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            print(f"[+] POST /api/auth/login: Authenticated '{username}'")

            # 4. Verify Profile
            r = client.get("/api/auth/me", headers=headers)
            assert r.status_code == 200, f"Auth me failed: {r.text}"
            profile = r.json()
            print(f"[+] GET /api/auth/me: {profile['username']} @ {profile['org_name']}")

            # 5. Pre-Flight Validation & Live IOC Lookup
            bad_r = client.post(
                "/api/lookup",
                json={"ioc_value": "invalid-ip-format", "ioc_type": "ip"},
                headers=headers,
            )
            assert bad_r.status_code == 400, f"Expected 400 for malformed IOC, got {bad_r.status_code}"
            print("[+] POST /api/lookup (malformed input): Rejected with 400 as expected")

            r = client.post(
                "/api/lookup",
                json={"ioc_value": "198.51.100.24", "ioc_type": "ip"},
                headers=headers,
            )
            assert r.status_code == 200, f"Live lookup failed: {r.text}"
            lookup_res = r.json()
            print(
                f"[+] POST /api/lookup: Verdict={lookup_res.get('verdict')} "
                f"(Score={lookup_res.get('confidence_score')})"
            )

            # 6. Watchlist Add & Query
            r = client.post(
                "/api/watchlist",
                json={"org_id": org_id, "ioc_value": "198.51.100.24", "ioc_type": "ip"},
                headers=headers,
            )
            assert r.status_code == 200, f"Watchlist add failed: {r.text}"
            w_id = r.json().get("watchlist_id")

            r = client.get(f"/api/organizations/{org_id}/watchlist", headers=headers)
            assert r.status_code == 200, f"Get watchlist failed: {r.text}"
            items = r.json()["watchlist"]
            print(f"[+] GET /api/organizations/{org_id}/watchlist: {len(items)} item(s)")

            # 7. Dashboard Correlation, Alerts & Wazuh Feed
            r = client.get("/api/correlation", headers=headers)
            assert r.status_code == 200, f"Correlation endpoint failed: {r.text}"
            print("[+] GET /api/correlation: Dashboard metrics retrieved")

            r = client.get("/api/alerts", headers=headers)
            assert r.status_code == 200, f"Alerts endpoint failed: {r.text}"
            print(f"[+] GET /api/alerts: {len(r.json().get('alerts', []))} alert(s)")

            r = client.get("/api/feed", headers=headers)
            assert r.status_code == 200, f"Wazuh feed endpoint failed: {r.text}"
            print("[+] GET /api/feed: Wazuh threat feed accessible")

            # 8. SIEM Config & STIX 2.1 Export
            r = client.post(
                f"/api/organizations/{org_id}/siem/config",
                json={
                    "siem_type": "splunk",
                    "endpoint_url": "https://splunk.sentinel.org:8088/services/collector/raw",
                    "auth_token": "live-test-splunk-token",
                    "sync_mode": "push",
                },
                headers=headers,
            )
            assert r.status_code == 200, f"SIEM config failed: {r.text}"
            print("[+] POST /api/organizations/{org_id}/siem/config: Saved Splunk HEC config")

            if w_id:
                r = client.get(f"/api/export/stix21/{w_id}", headers=headers)
                assert r.status_code == 200, f"STIX export failed: {r.text}"
                bundle = r.json()
                assert bundle.get("type") == "bundle"
                assert len(bundle.get("objects", [])) == 1
                print(f"[+] GET /api/export/stix21/{w_id}: Valid STIX 2.1 bundle verified")

            print("\nALL LIVE SERVER & END-TO-END HTTP CHECKS PASSED!")

    except httpx.ConnectError:
        print(
            f"\n[!] Could not connect to {BASE_URL}. Start the backend server first:\n"
            "    uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload"
        )
        sys.exit(1)


if __name__ == "__main__":
    run_live_smoke_test()