"""
Threat Intelligence Service – Day 2 (Mock Implementation).

This module contains mock functions that simulate external threat intelligence
API calls. In Day 3+ these will be replaced with real HTTP calls to:
  - AbuseIPDB  (https://www.abuseipdb.com/api)
  - VirusTotal (https://www.virustotal.com/api/v3)

Architecture
------------
All public functions are synchronous (Day 2). They will be converted to
async in Day 3 when real HTTP calls are introduced.

Usage
-----
    from app.services.threat_intelligence import enrich_ip
    result = enrich_ip("203.0.113.42")
"""

import hashlib
import random
import logging
from typing import Dict, Any

logger = logging.getLogger("soar.threat_intel")

# ── Known-bad IP seed list (simulated blocklist) ─────────────────────────────
# These IPs are treated as "known malicious" in mock mode.
_KNOWN_MALICIOUS_IPS = {
    "185.220.101.9",
    "45.33.32.156",
    "198.51.100.17",
    "203.0.113.42",
    "192.0.2.88",
    "198.18.0.7",
    "162.247.74.200",
    "5.188.10.76",
    "91.108.56.100",
    "194.165.16.10",
}

# ── Deterministic seed from IP ─────────────────────────────────────────────
def _ip_seed(ip: str) -> int:
    """Return a deterministic integer seed derived from the IP string."""
    return int(hashlib.md5(ip.encode()).hexdigest(), 16) % (2 ** 31)


# ── AbuseIPDB mock ────────────────────────────────────────────────────────────

def check_abuseipdb(ip: str) -> Dict[str, Any]:
    """
    Mock AbuseIPDB lookup.

    Returns a dict mimicking the AbuseIPDB v2 API response structure:
      - abuseConfidenceScore : 0-100 (how confident the IP is malicious)
      - totalReports         : Total number of abuse reports
      - countryCode          : ISO 3166-1 alpha-2 country code
      - isp                  : Internet Service Provider name
      - usageType            : e.g. 'Data Center/Web Hosting/Transit'
      - isPublic             : Whether the IP is publicly routable

    In production, replace this with:
        import httpx
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        return resp.json()["data"]
    """
    logger.info("[MOCK] AbuseIPDB check for IP: %s", ip)

    rng = random.Random(_ip_seed(ip))
    is_malicious = ip in _KNOWN_MALICIOUS_IPS

    if is_malicious:
        abuse_score = rng.randint(65, 100)
        total_reports = rng.randint(50, 500)
    else:
        abuse_score = rng.randint(0, 30)
        total_reports = rng.randint(0, 10)

    country_codes = ["US", "CN", "RU", "DE", "NL", "FR", "BR", "IN", "KR", "UA"]
    isps = [
        "DigitalOcean LLC", "Amazon AWS", "Cloudflare Inc",
        "Hetzner Online GmbH", "OVH SAS", "Linode LLC",
        "Google LLC", "Microsoft Azure", "Vultr Holdings",
    ]
    usage_types = [
        "Data Center/Web Hosting/Transit",
        "Commercial",
        "ISP/Mobile ISP",
        "Content Delivery Network",
    ]

    return {
        "ipAddress": ip,
        "isPublic": True,
        "abuseConfidenceScore": abuse_score,
        "totalReports": total_reports,
        "countryCode": rng.choice(country_codes),
        "isp": rng.choice(isps),
        "usageType": rng.choice(usage_types),
        "source": "AbuseIPDB (MOCK)",
    }


# ── VirusTotal mock ───────────────────────────────────────────────────────────

def check_virustotal(ip: str) -> Dict[str, Any]:
    """
    Mock VirusTotal IP reputation lookup.

    Returns a dict mimicking the VT API v3 /ip_addresses/{ip} stats structure:
      - malicious   : Number of AV engines flagging as malicious
      - suspicious  : Number of AV engines flagging as suspicious
      - undetected  : Number of AV engines with no detection
      - harmless    : Number of AV engines marking as harmless
      - reputation  : VT community reputation score (-100 to 100)

    In production, replace this with:
        import httpx
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
        )
        return resp.json()["data"]["attributes"]["last_analysis_stats"]
    """
    logger.info("[MOCK] VirusTotal check for IP: %s", ip)

    rng = random.Random(_ip_seed(ip) + 42)
    is_malicious = ip in _KNOWN_MALICIOUS_IPS

    total_engines = 90
    if is_malicious:
        malicious = rng.randint(15, 45)
        suspicious = rng.randint(5, 15)
    else:
        malicious = rng.randint(0, 3)
        suspicious = rng.randint(0, 5)

    harmless = rng.randint(20, 40)
    undetected = total_engines - malicious - suspicious - harmless

    return {
        "ip": ip,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": max(0, undetected),
        "harmless": harmless,
        "reputation": -malicious * 2 if is_malicious else rng.randint(0, 50),
        "source": "VirusTotal (MOCK)",
    }


# ── Aggregated enrichment ─────────────────────────────────────────────────────

def enrich_ip(ip: str) -> Dict[str, Any]:
    """
    Run all mock threat intelligence checks for a given IP and return
    a unified enrichment result.

    Parameters
    ----------
    ip : str
        Valid IPv4 address to enrich.

    Returns
    -------
    dict with keys:
        ip, abuseipdb, virustotal, is_known_malicious,
        abuseipdb_score, abuseipdb_reports,
        virustotal_malicious, virustotal_suspicious
    """
    abuse = check_abuseipdb(ip)
    vt = check_virustotal(ip)
    is_malicious = ip in _KNOWN_MALICIOUS_IPS or abuse["abuseConfidenceScore"] >= 60

    enrichment = {
        "ip": ip,
        "abuseipdb": abuse,
        "virustotal": vt,
        "is_known_malicious": is_malicious,
        # Flat summary fields (used by risk scoring engine)
        "abuseipdb_score": abuse["abuseConfidenceScore"],
        "abuseipdb_reports": abuse["totalReports"],
        "virustotal_malicious": vt["malicious"],
        "virustotal_suspicious": vt["suspicious"],
    }

    logger.info(
        "[MOCK] Enrichment complete for %s | abuse=%d | vt_malicious=%d | known_bad=%s",
        ip,
        enrichment["abuseipdb_score"],
        enrichment["virustotal_malicious"],
        enrichment["is_known_malicious"],
    )
    return enrichment
