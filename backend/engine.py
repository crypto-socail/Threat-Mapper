import ipaddress
import re
from typing import Any, Dict, List, Literal, Tuple
from urllib.parse import urlparse, urlunparse

AllowedIOCType = Literal["ip", "domain", "url", "hash", "email"]


def validate_and_normalize_ioc(ioc_value: str, ioc_type: str) -> str:
    """
    Normalizes and strictly validates an IOC before hitting external OSINT APIs.
    Preserves URL path/query case sensitivity while lowercasing domains, IPs, hashes, and emails.
    """
    raw_ioc = ioc_value.strip()
    if not raw_ioc:
        raise ValueError("IOC value cannot be empty")

    ioc_type_clean = ioc_type.strip().lower()

    if ioc_type_clean == "ip":
        clean_ioc = raw_ioc.lower()
        try:
            ipaddress.ip_address(clean_ioc)
        except ValueError:
            raise ValueError(f"Invalid IPv4/IPv6 address: {clean_ioc}")
        return clean_ioc

    if ioc_type_clean == "hash":
        clean_ioc = raw_ioc.lower()
        if not re.match(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", clean_ioc):
            raise ValueError("Invalid hash format (expected 32-char MD5, 40-char SHA-1, or 64-char SHA-256)")
        return clean_ioc

    if ioc_type_clean == "domain":
        clean_ioc = raw_ioc.lower().rstrip(".")
        if len(clean_ioc) > 253 or not re.match(
            r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", clean_ioc
        ):
            raise ValueError(f"Invalid domain format: {clean_ioc}")
        return clean_ioc

    if ioc_type_clean == "url":
        parsed = urlparse(raw_ioc)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"Invalid HTTP/HTTPS URL format: {raw_ioc}")
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            parsed.query,
            "",
        ))

    if ioc_type_clean == "email":
        clean_ioc = raw_ioc.lower()
        if not re.match(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}$", clean_ioc):
            raise ValueError(f"Invalid email format: {clean_ioc}")
        return clean_ioc

    raise ValueError(f"Unsupported IOC type '{ioc_type}'. Allowed: ip, domain, url, hash, email")


def evaluate_sources(source_results: Dict[str, Any]) -> Tuple[float, str, List[str], List[str]]:
    """
    Computes confidence score using only applicable sources that responded without errors.
    Returns (confidence_score, verdict, evaluated_sources, warnings).
    """
    weights = {
        "virustotal": 10.0,
        "abuseipdb": 7.0,
        "urlhaus": 8.0,
        "misp": 9.0,
        "hibp": 6.0,
    }

    total_evaluated_weight = 0.0
    total_flagged_weight = 0.0
    evaluated_sources: List[str] = []
    warnings: List[str] = []

    for source, data in source_results.items():
        if source not in weights or not isinstance(data, dict):
            continue
        if data.get("applicable") is False:
            continue
        if data.get("error"):
            warnings.append(f"{source}: {data['error']}")
            continue

        evaluated_sources.append(source)
        total_evaluated_weight += weights[source]
        if data.get("is_flagged"):
            total_flagged_weight += weights[source]

    if total_evaluated_weight == 0:
        return 0.0, "not currently known as bad", evaluated_sources, warnings

    confidence_score = round((total_flagged_weight / total_evaluated_weight) * 100, 2)

    if confidence_score > 60:
        verdict = "malicious"
    elif confidence_score >= 21:
        verdict = "suspicious"
    else:
        verdict = "not currently known as bad"

    return confidence_score, verdict, evaluated_sources, warnings


def calculate_confidence_score(source_results: Dict[str, Any]) -> Tuple[float, str]:
    """Backwards-compatible wrapper returning (confidence_score, verdict)."""
    score, verdict, _, _ = evaluate_sources(source_results)
    return score, verdict