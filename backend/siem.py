from datetime import datetime, timezone
import httpx
from auth import validate_outbound_siem_url


async def push_to_splunk(endpoint_url: str, auth_token: str, ioc_data: dict) -> bool:
    """Validates outbound target against SSRF and pushes a threat alert to Splunk HEC."""
    try:
        safe_url = validate_outbound_siem_url(endpoint_url)
    except ValueError as e:
        print(f"        -> [SECURITY] Blocked unsafe SIEM URL: {e}", flush=True)
        return False

    headers = {
        "Authorization": f"Splunk {auth_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "time": datetime.now(timezone.utc).timestamp(),
        "sourcetype": "threatmapper:alert",
        "event": ioc_data,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.post(safe_url, json=payload, headers=headers)
            response.raise_for_status()
            return True
    except Exception as e:
        print(f"        -> Splunk Push Failed: {e}", flush=True)
        return False