import os
import urllib.parse
import httpx
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
MISP_URL = os.getenv("MISP_URL")
MISP_AUTH_KEY = os.getenv("MISP_AUTH_KEY")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"
HIBP_API_KEY = os.getenv("HIBP_API_KEY")


async def fetch_virustotal(ioc_value: str, ioc_type: str) -> dict:
    if ioc_type not in ("ip", "hash"):
        return {"is_flagged": False, "applicable": False}
    if not VT_API_KEY or VT_API_KEY == "your_vt_api_key_here":
        return {"is_flagged": False, "applicable": False}

    url = (
        f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
        if ioc_type == "ip"
        else f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    )
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=10.0)
            if response.status_code == 429:
                return {"is_flagged": False, "applicable": True, "error": "QuotaExceeded"}
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {"is_flagged": stats.get("malicious", 0) > 0, "applicable": True}
            return {"is_flagged": False, "applicable": True, "error": f"HTTP_{response.status_code}"}
        except Exception as e:
            return {"is_flagged": False, "applicable": True, "error": type(e).__name__}


async def fetch_abuseipdb(ioc_value: str, ioc_type: str) -> dict:
    if ioc_type != "ip":
        return {"is_flagged": False, "applicable": False}
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your_abuseipdb_key_here":
        return {"is_flagged": False, "applicable": False}

    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ioc_value, "maxAgeInDays": "90"}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10.0
            )
            if response.status_code == 429:
                return {"is_flagged": False, "applicable": True, "error": "QuotaExceeded"}
            if response.status_code == 200:
                score = response.json().get("data", {}).get("abuseConfidenceScore", 0)
                return {"is_flagged": score > 50, "applicable": True}
            return {"is_flagged": False, "applicable": True, "error": f"HTTP_{response.status_code}"}
        except Exception as e:
            return {"is_flagged": False, "applicable": True, "error": type(e).__name__}


async def fetch_urlhaus(ioc_value: str, ioc_type: str) -> dict:
    if ioc_type not in ("ip", "domain", "url", "hash"):
        return {"is_flagged": False, "applicable": False}

    headers = {}
    if URLHAUS_API_KEY and URLHAUS_API_KEY != "your_urlhaus_key_here":
        headers["Auth-Key"] = URLHAUS_API_KEY

    if ioc_type in ("ip", "domain"):
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        data = {"host": ioc_value}
    elif ioc_type == "url":
        url = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {"url": ioc_value}
    else:
        url = "https://urlhaus-api.abuse.ch/v1/payload/"
        if len(ioc_value) == 32:
            data = {"md5_hash": ioc_value}
        elif len(ioc_value) == 64:
            data = {"sha256_hash": ioc_value}
        else:
            return {"is_flagged": False, "applicable": False}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, headers=headers, data=data, timeout=10.0)
            if response.status_code == 429:
                return {"is_flagged": False, "applicable": True, "error": "QuotaExceeded"}
            if response.status_code == 200:
                return {"is_flagged": response.json().get("query_status") == "ok", "applicable": True}
            return {"is_flagged": False, "applicable": True, "error": f"HTTP_{response.status_code}"}
        except Exception as e:
            return {"is_flagged": False, "applicable": True, "error": type(e).__name__}


async def fetch_misp(ioc_value: str, ioc_type: str) -> dict:
    if not MISP_URL or MISP_URL == "https://your-misp-instance.com" or not MISP_AUTH_KEY:
        return {"is_flagged": False, "applicable": False}

    url = f"{MISP_URL.rstrip('/')}/attributes/restSearch"
    headers = {
        "Authorization": MISP_AUTH_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {"value": ioc_value, "returnFormat": "json"}

    async with httpx.AsyncClient(verify=MISP_VERIFY_SSL) as client:
        try:
            response = await client.post(url, headers=headers, json=payload, timeout=10.0)
            if response.status_code == 429:
                return {"is_flagged": False, "applicable": True, "error": "QuotaExceeded"}
            if response.status_code == 200:
                attributes = response.json().get("response", {}).get("Attribute", [])
                return {"is_flagged": len(attributes) > 0, "applicable": True}
            return {"is_flagged": False, "applicable": True, "error": f"HTTP_{response.status_code}"}
        except Exception as e:
            return {"is_flagged": False, "applicable": True, "error": type(e).__name__}


async def fetch_hibp(ioc_value: str, ioc_type: str) -> dict:
    if ioc_type != "email":
        return {"is_flagged": False, "applicable": False}
    if not HIBP_API_KEY or HIBP_API_KEY == "your_haveibeenpwned_key":
        return {"is_flagged": False, "applicable": False}

    encoded_email = urllib.parse.quote(ioc_value)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}?truncateResponse=false"
    headers = {"hibp-api-key": HIBP_API_KEY, "user-agent": "ThreatMapper-OSINT-Engine"}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=10.0)
            if response.status_code == 429:
                return {"is_flagged": False, "applicable": True, "error": "QuotaExceeded"}
            if response.status_code == 200:
                return {"is_flagged": len(response.json()) > 0, "applicable": True}
            if response.status_code == 404:
                return {"is_flagged": False, "applicable": True}
            return {"is_flagged": False, "applicable": True, "error": f"HTTP_{response.status_code}"}
        except Exception as e:
            return {"is_flagged": False, "applicable": True, "error": type(e).__name__}