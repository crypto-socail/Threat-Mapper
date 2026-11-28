from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "").strip()
MISP_URL = os.getenv("MISP_URL", "").strip().rstrip("/")
MISP_AUTH_KEY = os.getenv("MISP_AUTH_KEY", "").strip()
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "true").strip().lower() in ("1", "true", "yes")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()

DEFAULT_TIMEOUT = httpx.Timeout(12.0, connect=5.0)
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def detect_ioc_type(value: str) -> str:
    val = value.strip()
    try:
        ipaddress.ip_address(val)
        return "ip"
    except ValueError:
        pass

    if HASH_RE.match(val):
        return "hash"

    if "@" in val and "." in val.split("@")[-1] and " " not in val:
        return "email"

    parsed = urlparse(val)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return "url"

    return "domain"


def _unavailable(source: str, reason: str = "Not configured") -> dict[str, Any]:
    return {
        "source": source,
        "available": False,
        "applicable": False,
        "is_flagged": False,
        "score": 0,
        "error": None,
        "reason": reason,
        "details": {},
    }


def _not_applicable(source: str, reason: str) -> dict[str, Any]:
    return {
        "source": source,
        "available": True,
        "applicable": False,
        "is_flagged": False,
        "score": 0,
        "error": None,
        "reason": reason,
        "details": {},
    }


def _errored(source: str, err: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "source": source,
        "available": True,
        "applicable": True,
        "is_flagged": False,
        "score": 0,
        "error": err,
        "reason": err,
        "details": details or {},
    }


def _extract_tls_info(attrs: dict[str, Any]) -> dict[str, Any]:
    cert = attrs.get("last_https_certificate") or {}
    issuer = cert.get("issuer") or {}
    subject = cert.get("subject") or {}
    validity = cert.get("validity") or {}
    return {
        "tls_issuer": issuer.get("O") or issuer.get("CN"),
        "tls_subject": subject.get("CN") or subject.get("O"),
        "tls_valid_from": validity.get("not_before"),
        "tls_valid_to": validity.get("not_after"),
        "tls_version": cert.get("version"),
        "tls_cipher": attrs.get("last_https_certificate_cipher") or cert.get("cipher"),
    }


async def query_virustotal(ioc_value: str, ioc_type: str) -> dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", VT_API_KEY).strip()
    if not api_key:
        return _unavailable("virustotal", "VIRUSTOTAL_API_KEY not set")

    val = ioc_value.strip()
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{val}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{val}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(val.encode()).decode().rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif ioc_type in ("hash", "file"):
        url = f"https://www.virustotal.com/api/v3/files/{val}"
    else:
        return _not_applicable("virustotal", f"Unsupported IOC type: {ioc_type}")

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code == 404:
            return {
                "source": "virustotal",
                "available": True,
                "applicable": True,
                "is_flagged": False,
                "score": 0,
                "error": None,
                "reason": "Not found in VirusTotal dataset",
                "details": {"not_found": True},
            }
        if resp.status_code == 429:
            return _errored("virustotal", "Rate limit exceeded (HTTP 429)")
        resp.raise_for_status()
        payload = resp.json()
        attrs = (payload.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total_engines = max(malicious + suspicious + harmless + undetected, 1)
        flagged_count = malicious + suspicious

        details: dict[str, Any] = {
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "total_engines": total_engines,
            "detection_ratio": f"{flagged_count}/{total_engines}",
            "reputation": attrs.get("reputation"),
            "tags": (attrs.get("tags") or [])[:8],
        }

        if ioc_type == "ip":
            details.update({
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "network": attrs.get("network"),
                **_extract_tls_info(attrs),
            })
        elif ioc_type in ("domain", "url"):
            details.update({
                "registrar": attrs.get("registrar"),
                "categories": attrs.get("categories") or {},
                "last_http_status": attrs.get("last_http_response_code"),
                "title": attrs.get("title"),
                **_extract_tls_info(attrs),
            })
        elif ioc_type in ("hash", "file"):
            sig_info = attrs.get("signature_info") or {}
            threat_class = attrs.get("popular_threat_classification") or {}
            suggested_label = threat_class.get("suggested_threat_label")
            top_category = None
            cats = threat_class.get("popular_threat_category") or []
            if cats and isinstance(cats, list):
                top_category = cats[0].get("value") if isinstance(cats[0], dict) else str(cats[0])
            details.update({
                "file_type": attrs.get("type_description"),
                "file_size": attrs.get("size"),
                "meaningful_name": attrs.get("meaningful_name"),
                "md5": attrs.get("md5"),
                "sha1": attrs.get("sha1"),
                "sha256": attrs.get("sha256"),
                "signed": bool(sig_info.get("verified") or sig_info.get("product")),
                "signer": sig_info.get("product") or sig_info.get("description") or sig_info.get("copyright"),
                "threat_label": suggested_label or top_category,
            })

        is_flagged = malicious > 0 or suspicious >= 2
        raw_score = min(100.0, round((flagged_count / total_engines) * 100.0 + (malicious * 15.0), 1))
        return {
            "source": "virustotal",
            "available": True,
            "applicable": True,
            "is_flagged": is_flagged,
            "score": raw_score if is_flagged else 0.0,
            "error": None,
            "reason": f"{flagged_count}/{total_engines} engines flagged ({malicious} malicious, {suspicious} suspicious)",
            "details": details,
        }
    except httpx.TimeoutException:
        return _errored("virustotal", "Request timed out")
    except httpx.HTTPError as exc:
        return _errored("virustotal", f"HTTP error: {exc}")
    except Exception as exc:
        return _errored("virustotal", f"Unexpected error: {exc}")


async def query_abuseipdb(ioc_value: str, ioc_type: str) -> dict[str, Any]:
    if ioc_type != "ip":
        return _not_applicable("abuseipdb", f"IP-only connector (skipped for {ioc_type})")

    api_key = os.getenv("ABUSEIPDB_API_KEY", ABUSEIPDB_API_KEY).strip()
    if not api_key:
        return _unavailable("abuseipdb", "ABUSEIPDB_API_KEY not set")

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ioc_value.strip(), "maxAgeInDays": "90", "verbose": ""}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        if resp.status_code == 429:
            return _errored("abuseipdb", "Rate limit exceeded (HTTP 429)")
        resp.raise_for_status()
        data = (resp.json() or {}).get("data") or {}
        abuse_score = float(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))
        is_flagged = abuse_score >= 25 or total_reports >= 3
        details = {
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "hostnames": (data.get("hostnames") or [])[:5],
            "total_reports": total_reports,
            "abuse_confidence_score": abuse_score,
            "is_tor": bool(data.get("isTor")),
        }
        return {
            "source": "abuseipdb",
            "available": True,
            "applicable": True,
            "is_flagged": is_flagged,
            "score": abuse_score,
            "error": None,
            "reason": f"Abuse confidence {abuse_score}% across {total_reports} reports",
            "details": details,
        }
    except httpx.TimeoutException:
        return _errored("abuseipdb", "Request timed out")
    except httpx.HTTPError as exc:
        return _errored("abuseipdb", f"HTTP error: {exc}")
    except Exception as exc:
        return _errored("abuseipdb", f"Unexpected error: {exc}")


async def query_urlhaus(ioc_value: str, ioc_type: str) -> dict[str, Any]:
    if ioc_type not in ("url", "domain", "ip", "hash"):
        return _not_applicable("urlhaus", f"Not applicable for {ioc_type}")

    auth_key = os.getenv("URLHAUS_API_KEY", URLHAUS_API_KEY).strip()
    if not auth_key:
        return _unavailable("urlhaus", "URLHAUS_API_KEY not set")

    val = ioc_value.strip()
    if ioc_type == "url":
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        form_data = {"url": val}
    elif ioc_type == "hash":
        endpoint = "https://urlhaus-api.abuse.ch/v1/payload/"
        hash_key = "sha256_hash" if len(val) == 64 else "md5_hash"
        form_data = {hash_key: val}
    else:
        endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        form_data = {"host": val}

    headers = {"Auth-Key": auth_key}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.post(endpoint, headers=headers, data=form_data)
        if resp.status_code == 429:
            return _errored("urlhaus", "Rate limit exceeded (HTTP 429)")
        resp.raise_for_status()
        body = resp.json() or {}
        query_status = body.get("query_status")

        if query_status in ("no_results", "ok_no_results"):
            return {
                "source": "urlhaus",
                "available": True,
                "applicable": True,
                "is_flagged": False,
                "score": 0,
                "error": None,
                "reason": "No active malware listings in URLhaus",
                "details": {"query_status": query_status},
            }

        threat = body.get("threat") or (body.get("payload") or {}).get("signature")
        tags = body.get("tags") or []
        url_status = body.get("url_status")
        urls = body.get("urls") or []
        if not threat and urls and isinstance(urls, list):
            threat = urls[0].get("threat")
            url_status = urls[0].get("url_status")
            tags = tags or (urls[0].get("tags") or [])

        is_flagged = query_status == "ok" and (bool(threat) or url_status == "online" or len(urls) > 0)
        details = {
            "query_status": query_status,
            "threat": threat,
            "url_status": url_status,
            "tags": tags[:8] if isinstance(tags, list) else [],
            "active_urls_count": len(urls) if isinstance(urls, list) else 0,
        }
        return {
            "source": "urlhaus",
            "available": True,
            "applicable": True,
            "is_flagged": is_flagged,
            "score": 85.0 if is_flagged else 0.0,
            "error": None,
            "reason": f"URLhaus match ({threat or query_status})",
            "details": details,
        }
    except httpx.TimeoutException:
        return _errored("urlhaus", "Request timed out")
    except httpx.HTTPError as exc:
        return _errored("urlhaus", f"HTTP error: {exc}")
    except Exception as exc:
        return _errored("urlhaus", f"Unexpected error: {exc}")


async def query_misp(ioc_value: str, ioc_type: str) -> dict[str, Any]:
    misp_url = os.getenv("MISP_URL", MISP_URL).strip().rstrip("/")
    misp_key = os.getenv("MISP_AUTH_KEY", MISP_AUTH_KEY).strip()
    verify_ssl = os.getenv("MISP_VERIFY_SSL", str(MISP_VERIFY_SSL)).strip().lower() in ("1", "true", "yes")

    if not misp_url or not misp_key:
        return _unavailable("misp", "MISP_URL or MISP_AUTH_KEY not configured")

    type_map = {
        "ip": "ip-dst",
        "domain": "domain",
        "url": "url",
        "hash": "sha256",
        "file": "sha256",
        "email": "email-src",
    }
    misp_type = type_map.get(ioc_type)
    if not misp_type:
        return _not_applicable("misp", f"No MISP attribute mapping for {ioc_type}")

    headers = {
        "Authorization": misp_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {"returnFormat": "json", "value": ioc_value.strip(), "type": misp_type}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, verify=verify_ssl) as client:
            resp = await client.post(f"{misp_url}/attributes/rest/search", headers=headers, json=payload)
        resp.raise_for_status()
        attributes = ((resp.json() or {}).get("response") or {}).get("Attribute") or []
        is_flagged = len(attributes) > 0
        event_titles = []
        for attr in attributes[:5]:
            ev = attr.get("Event") or {}
            if ev.get("info"):
                event_titles.append(ev["info"])
        return {
            "source": "misp",
            "available": True,
            "applicable": True,
            "is_flagged": is_flagged,
            "score": 80.0 if is_flagged else 0.0,
            "error": None,
            "reason": f"{len(attributes)} matching MISP attribute(s)" if is_flagged else "No matching MISP attributes",
            "details": {
                "matched_attributes": len(attributes),
                "events": event_titles,
            },
        }
    except httpx.TimeoutException:
        return _errored("misp", "Request timed out")
    except httpx.HTTPError as exc:
        return _errored("misp", f"HTTP error: {exc}")
    except Exception as exc:
        return _errored("misp", f"Unexpected error: {exc}")


async def query_hibp(ioc_value: str, ioc_type: str) -> dict[str, Any]:
    if ioc_type != "email":
        return _not_applicable("hibp", f"Email-only connector (skipped for {ioc_type})")

    api_key = os.getenv("HIBP_API_KEY", HIBP_API_KEY).strip()
    if not api_key:
        return _unavailable("hibp", "HIBP_API_KEY not set")

    headers = {
        "hibp-api-key": api_key,
        "User-Agent": "ThreatMapper-v2-SOC",
        "Accept": "application/json",
    }
    params = {"truncateResponse": "false"}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{ioc_value.strip()}",
                headers=headers,
                params=params,
            )
        if resp.status_code == 404:
            return {
                "source": "hibp",
                "available": True,
                "applicable": True,
                "is_flagged": False,
                "score": 0,
                "error": None,
                "reason": "No known breach records",
                "details": {"breach_count": 0, "breaches": []},
            }
        if resp.status_code == 429:
            return _errored("hibp", "Rate limit exceeded (HTTP 429)")
        resp.raise_for_status()
        breaches = resp.json() if isinstance(resp.json(), list) else []
        is_flagged = len(breaches) > 0
        breach_names = [b.get("Name") for b in breaches[:8] if b.get("Name")]
        data_classes: list[str] = []
        for b in breaches:
            for dc in b.get("DataClasses") or []:
                if dc not in data_classes:
                    data_classes.append(dc)
        return {
            "source": "hibp",
            "available": True,
            "applicable": True,
            "is_flagged": is_flagged,
            "score": min(100.0, round(len(breaches) * 20.0, 1)) if is_flagged else 0.0,
            "error": None,
            "reason": f"Found in {len(breaches)} breach(es)" if is_flagged else "Clean",
            "details": {
                "breach_count": len(breaches),
                "breaches": breach_names,
                "exposed_data_classes": data_classes[:10],
            },
        }
    except httpx.TimeoutException:
        return _errored("hibp", "Request timed out")
    except httpx.HTTPError as exc:
        return _errored("hibp", f"HTTP error: {exc}")
    except Exception as exc:
        return _errored("hibp", f"Unexpected error: {exc}")


def compute_sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()