"""
Threat Intelligence Service Layer
==================================
Unified TI lookup with real API support and automatic mock fallback.

Sources:
  1. AbuseIPDB  v2  — abuse confidence + reports
  2. VirusTotal v3  — malicious engine count + reputation
  3. IPInfo         — geolocation, ASN, org
"""

from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

from app.config import settings
from app.utils.helpers import get_logger

logger = get_logger(__name__)

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
    logger.warning("requests library not installed – real TI API calls unavailable.")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rng(ip: str, salt: str = "") -> random.Random:
    seed = int(hashlib.md5((ip + salt).encode()).hexdigest(), 16) % (2 ** 32)
    return random.Random(seed)


_KNOWN_BAD_IPS = {
    "203.0.113.42",
    "198.51.100.17",
    "45.33.32.156",
    "185.220.101.9",
    "192.0.2.88",
}


def _is_bad(ip: str) -> bool:
    return ip in _KNOWN_BAD_IPS


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def _real_abuseipdb(ip: str) -> Dict[str, Any]:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": settings.TI_MAX_DAYS_CHECK, "verbose": ""}
    resp = _requests.get(url, headers=headers, params=params, timeout=settings.TI_REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return {
        "ip_address":             data.get("ipAddress", ip),
        "is_public":              data.get("isPublic", True),
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "country_code":           data.get("countryCode", ""),
        "isp":                    data.get("isp", ""),
        "domain":                 data.get("domain"),
        "total_reports":          data.get("totalReports", 0),
        "last_reported_at":       data.get("lastReportedAt"),
        "is_whitelisted":         data.get("isWhitelisted", False),
        "usage_type":             data.get("usageType", ""),
        "source":                 "AbuseIPDB (live)",
    }


def _mock_abuseipdb(ip: str) -> Dict[str, Any]:
    r = _rng(ip)
    bad = _is_bad(ip)
    if bad:
        confidence    = r.randint(65, 100)
        total_reports = r.randint(50, 500)
        country_code  = r.choice(["RU", "CN", "KP", "IR", "BR"])
        isp           = r.choice(["Sharktech", "Vultr Holdings LLC", "Digital Ocean"])
        usage_type    = "Data Center/Web Hosting/Transit"
        is_public     = True
        domain        = None
    else:
        confidence    = r.randint(0, 20)
        total_reports = r.randint(0, 5)
        country_code  = r.choice(["US", "DE", "GB", "JP", "CA"])
        isp           = r.choice(["Cloudflare Inc", "Amazon Technologies", "Google LLC"])
        usage_type    = "Commercial"
        is_public     = not ip.startswith(("10.", "192.168.", "172.16."))
        domain        = r.choice(["cdn.example.com", "proxy.example.net", None])

    last_reported = (datetime.now(timezone.utc) - timedelta(days=r.randint(1, 30))).isoformat()
    return {
        "ip_address":             ip,
        "is_public":              is_public,
        "abuse_confidence_score": confidence,
        "country_code":           country_code,
        "isp":                    isp,
        "domain":                 domain,
        "total_reports":          total_reports,
        "last_reported_at":       last_reported,
        "is_whitelisted":         False,
        "usage_type":             usage_type,
        "source":                 "AbuseIPDB (mock)",
    }


def check_abuseipdb(ip: str) -> Dict[str, Any]:
    if settings.abuseipdb_enabled and _REQUESTS_AVAILABLE:
        logger.info("TI | AbuseIPDB LIVE | ip=%s", ip)
        try:
            return _real_abuseipdb(ip)
        except Exception as exc:
            logger.warning("TI | AbuseIPDB LIVE failed (%s) – using mock.", exc)
    logger.info("TI | AbuseIPDB mock | ip=%s", ip)
    return _mock_abuseipdb(ip)


# ── VirusTotal ────────────────────────────────────────────────────────────────

def _real_virustotal(ip: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    resp = _requests.get(url, headers=headers, timeout=settings.TI_REQUEST_TIMEOUT)
    resp.raise_for_status()
    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values()) or 90
    return {
        "ip_address":                ip,
        "malicious_count":           stats.get("malicious", 0),
        "suspicious_count":          stats.get("suspicious", 0),
        "harmless_count":            stats.get("harmless", 0),
        "undetected_count":          stats.get("undetected", 0),
        "total_engines":             total,
        "reputation":                attrs.get("reputation", 0),
        "network":                   attrs.get("network", ""),
        "asn":                       attrs.get("asn", 0),
        "as_owner":                  attrs.get("as_owner", ""),
        "country":                   attrs.get("country", ""),
        "regional_internet_registry": attrs.get("regional_internet_registry", ""),
        "last_analysis_date":        datetime.fromtimestamp(
            attrs.get("last_analysis_date", 0), tz=timezone.utc).isoformat(),
        "tags":                      attrs.get("tags", []),
        "source":                    "VirusTotal (live)",
    }


def _mock_virustotal(ip: str) -> Dict[str, Any]:
    r = _rng(ip, salt="vt")
    bad = _is_bad(ip)
    total = 90
    if bad:
        malicious  = r.randint(15, 45)
        suspicious = r.randint(3, 10)
        harmless   = r.randint(20, 40)
        reputation = r.randint(-100, -10)
        tags       = r.sample(["malware", "botnet", "c2", "phishing", "scanner", "tor-exit-node"], k=3)
        asn        = r.randint(200000, 400000)
        rir        = r.choice(["RIPE", "APNIC", "LACNIC"])
        owner      = r.choice(["Frantech Solutions", "M247 Europe SRL", "Shock Hosting LLC"])
        country    = r.choice(["RU", "CN", "KP", "NL", "BG"])
    else:
        malicious  = r.randint(0, 2)
        suspicious = r.randint(0, 3)
        harmless   = r.randint(60, 80)
        reputation = r.randint(0, 50)
        tags       = []
        asn        = r.randint(10000, 200000)
        rir        = r.choice(["ARIN", "RIPE"])
        owner      = r.choice(["Amazon.com Inc", "Google LLC", "Microsoft Corporation"])
        country    = r.choice(["US", "DE", "GB", "JP"])

    undetected = max(total - malicious - suspicious - harmless, 0)
    parts      = ip.split(".")
    network    = f"{parts[0]}.{parts[1]}.0.0/16"
    last_analysis = (datetime.now(timezone.utc) - timedelta(days=r.randint(1, 7))).isoformat()
    return {
        "ip_address":                ip,
        "malicious_count":           malicious,
        "suspicious_count":          suspicious,
        "harmless_count":            harmless,
        "undetected_count":          undetected,
        "total_engines":             total,
        "reputation":                reputation,
        "network":                   network,
        "asn":                       asn,
        "as_owner":                  owner,
        "country":                   country,
        "regional_internet_registry": rir,
        "last_analysis_date":        last_analysis,
        "tags":                      tags,
        "source":                    "VirusTotal (mock)",
    }


def check_virustotal(ip: str) -> Dict[str, Any]:
    if settings.virustotal_enabled and _REQUESTS_AVAILABLE:
        logger.info("TI | VirusTotal LIVE | ip=%s", ip)
        try:
            return _real_virustotal(ip)
        except Exception as exc:
            logger.warning("TI | VirusTotal LIVE failed (%s) – using mock.", exc)
    logger.info("TI | VirusTotal mock | ip=%s", ip)
    return _mock_virustotal(ip)


# ── IPInfo ────────────────────────────────────────────────────────────────────

def _real_ipinfo(ip: str) -> Dict[str, Any]:
    """Call the live IPInfo /api/{ip}/json endpoint."""
    token  = settings.IPINFO_API_KEY
    url    = f"https://ipinfo.io/{ip}/json"
    params = {"token": token} if token else {}
    resp   = _requests.get(url, params=params, timeout=settings.TI_REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return {
        "ip":       data.get("ip", ip),
        "hostname": data.get("hostname", ""),
        "city":     data.get("city", ""),
        "region":   data.get("region", ""),
        "country":  data.get("country", ""),
        "org":      data.get("org", ""),      # "AS15169 Google LLC"
        "asn":      data.get("org", "").split(" ")[0] if data.get("org") else "",
        "timezone": data.get("timezone", ""),
        "loc":      data.get("loc", ""),
        "source":   "IPInfo (live)",
    }


def _mock_ipinfo(ip: str) -> Dict[str, Any]:
    """Deterministic mock IPInfo response."""
    r   = _rng(ip, salt="ipinfo")
    bad = _is_bad(ip)
    if bad:
        country  = r.choice(["RU", "CN", "KP", "IR", "BR"])
        city     = r.choice(["Moscow", "Shanghai", "Pyongyang", "Tehran", "São Paulo"])
        org_name = r.choice(["Frantech Solutions", "M247 Europe SRL", "Shock Hosting LLC"])
        asn_num  = r.randint(200000, 400000)
        tz       = r.choice(["Europe/Moscow", "Asia/Shanghai", "Asia/Pyongyang"])
    else:
        country  = r.choice(["US", "DE", "GB", "JP", "CA"])
        city     = r.choice(["New York", "Berlin", "London", "Tokyo", "Toronto"])
        org_name = r.choice(["Amazon.com Inc", "Google LLC", "Microsoft Corporation", "Cloudflare"])
        asn_num  = r.randint(10000, 200000)
        tz       = r.choice(["America/New_York", "Europe/Berlin", "Europe/London"])

    asn = f"AS{asn_num}"
    return {
        "ip":       ip,
        "hostname": f"host-{ip.replace('.', '-')}.example.net",
        "city":     city,
        "region":   city,
        "country":  country,
        "org":      f"{asn} {org_name}",
        "asn":      asn,
        "timezone": tz,
        "loc":      f"{r.uniform(-90, 90):.4f},{r.uniform(-180, 180):.4f}",
        "source":   "IPInfo (mock)",
    }


def check_ipinfo(ip: str) -> Dict[str, Any]:
    """Get geolocation and ASN data for an IP from IPInfo."""
    if _REQUESTS_AVAILABLE:
        logger.info("TI | IPInfo | ip=%s live=%s", ip, settings.ipinfo_enabled)
        try:
            return _real_ipinfo(ip)
        except Exception as exc:
            logger.warning("TI | IPInfo LIVE failed (%s) – using mock.", exc)
    logger.info("TI | IPInfo mock | ip=%s", ip)
    return _mock_ipinfo(ip)


# ── Combined enrichment ───────────────────────────────────────────────────────

def enrich_ip(ip: str) -> Dict[str, Any]:
    """
    Run AbuseIPDB + VirusTotal + IPInfo lookups and return a combined report.

    Aggregate confidence:
      (AbuseIPDB_confidence * 0.6) + (VT_malicious_ratio * 100 * 0.4)

    Verdict:
      >= 60 → Malicious
      >= 25 → Suspicious
      <  25 → Clean
    """
    abuse  = check_abuseipdb(ip)
    vt     = check_virustotal(ip)
    ipinfo = check_ipinfo(ip)

    abuse_conf = abuse.get("abuse_confidence_score", 0)
    vt_ratio   = (vt.get("malicious_count", 0) / max(vt.get("total_engines", 90), 1)) * 100
    aggregate  = round(abuse_conf * 0.6 + vt_ratio * 0.4, 2)

    if aggregate >= 60:
        verdict = "Malicious"
    elif aggregate >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    logger.info(
        "TI | Enrichment done | ip=%s abuse=%d vt_mal=%d aggregate=%.2f verdict=%s",
        ip, abuse_conf, vt.get("malicious_count", 0), aggregate, verdict,
    )

    return {
        "ip_address":           ip,
        "abuseipdb":            abuse,
        "virustotal":           vt,
        "ipinfo":               ipinfo,
        "country":              ipinfo.get("country", abuse.get("country_code", "")),
        "city":                 ipinfo.get("city", "Unknown"),
        "asn":                  ipinfo.get("asn", ""),
        "org":                  ipinfo.get("org", abuse.get("isp", "")),
        "aggregate_confidence": aggregate,
        "threat_verdict":       verdict,
    }
