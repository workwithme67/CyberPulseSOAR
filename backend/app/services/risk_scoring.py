"""
Risk Scoring Engine – Day 2.

Calculates a dynamic risk score (0-100) for each security alert by
combining three independent signal sources:

  1. Severity weight   – Base score from the alert's severity level.
  2. AbuseIPDB signal  – Weighted contribution from the abuse confidence score.
  3. VirusTotal signal – Weighted contribution from malicious engine detections.

Risk Score Bands
----------------
  0  – 25  : Low
  26 – 50  : Medium
  51 – 75  : High
  76 – 100 : Critical

Scoring Formula
---------------
  raw_score = (severity_weight * 0.50)
            + (abuseipdb_score * 0.30)
            + (vt_contribution * 0.20)

  capped at 100, floored at 0, rounded to 2 decimal places.

Future enhancements (Day 4+):
  - Historical alert frequency for the source IP.
  - Asset criticality weighting (is the target a production server?).
  - Time-of-day modifier (off-hours alerts are higher risk).
  - Geo-location risk modifier.
"""

import logging
from typing import Dict, Any

from app.models.alert import SeverityLevel, RiskCategory

logger = logging.getLogger("soar.risk_scoring")


# ── Severity base weights (out of 100) ────────────────────────────────────────

SEVERITY_WEIGHTS: Dict[str, float] = {
    SeverityLevel.LOW: 15.0,
    SeverityLevel.MEDIUM: 40.0,
    SeverityLevel.HIGH: 70.0,
    SeverityLevel.CRITICAL: 95.0,
}

# ── Contribution weights ──────────────────────────────────────────────────────

WEIGHT_SEVERITY = 0.50    # 50% of score comes from severity
WEIGHT_ABUSEIPDB = 0.30   # 30% from AbuseIPDB score
WEIGHT_VIRUSTOTAL = 0.20  # 20% from VirusTotal detections

# ── VirusTotal normalisation (max engines that typically flag an IP) ──────────
VT_MAX_ENGINES = 90


# ── Core scoring function ─────────────────────────────────────────────────────

def calculate_risk_score(
    severity: str,
    abuseipdb_score: int,
    virustotal_malicious: int,
    virustotal_suspicious: int = 0,
) -> float:
    """
    Compute a numerical risk score in the range [0, 100].

    Parameters
    ----------
    severity              : SeverityLevel enum value (e.g. "HIGH").
    abuseipdb_score       : AbuseIPDB confidence score (0-100).
    virustotal_malicious  : Count of VT engines flagging as malicious.
    virustotal_suspicious : Count of VT engines flagging as suspicious.

    Returns
    -------
    float : Risk score rounded to 2 decimal places.
    """
    # 1. Severity component
    severity_base = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS[SeverityLevel.MEDIUM])
    severity_component = severity_base * WEIGHT_SEVERITY

    # 2. AbuseIPDB component (already 0-100)
    abuse_component = abuseipdb_score * WEIGHT_ABUSEIPDB

    # 3. VirusTotal component – normalise malicious + 0.5x suspicious detections
    vt_effective = min(virustotal_malicious + 0.5 * virustotal_suspicious, VT_MAX_ENGINES)
    vt_normalised = (vt_effective / VT_MAX_ENGINES) * 100
    vt_component = vt_normalised * WEIGHT_VIRUSTOTAL

    raw = severity_component + abuse_component + vt_component
    score = round(min(max(raw, 0.0), 100.0), 2)

    logger.debug(
        "risk_score: severity=%.1f abuse=%.1f vt=%.1f → total=%.2f",
        severity_component, abuse_component, vt_component, score,
    )
    return score


def get_risk_category(score: float) -> str:
    """
    Map a numeric risk score to a human-readable risk category label.

    Parameters
    ----------
    score : float in [0, 100]

    Returns
    -------
    str : One of 'Low', 'Medium', 'High', 'Critical'
    """
    if score <= 25:
        return RiskCategory.LOW
    elif score <= 50:
        return RiskCategory.MEDIUM
    elif score <= 75:
        return RiskCategory.HIGH
    else:
        return RiskCategory.CRITICAL


def score_alert(severity: str, enrichment: Dict[str, Any]) -> Dict[str, Any]:
    """
    High-level convenience function: compute score and category from an
    enrichment dict (as returned by threat_intelligence.enrich_ip).

    Parameters
    ----------
    severity   : SeverityLevel string.
    enrichment : Dict from ``enrich_ip()``.

    Returns
    -------
    dict with keys: score (float), category (str), breakdown (dict)
    """
    abuse_score = enrichment.get("abuseipdb_score", 0)
    vt_malicious = enrichment.get("virustotal_malicious", 0)
    vt_suspicious = enrichment.get("virustotal_suspicious", 0)

    score = calculate_risk_score(severity, abuse_score, vt_malicious, vt_suspicious)
    category = get_risk_category(score)

    return {
        "score": score,
        "category": category,
        "breakdown": {
            "severity_input": severity,
            "abuseipdb_score": abuse_score,
            "virustotal_malicious": vt_malicious,
            "virustotal_suspicious": vt_suspicious,
            "severity_weight": WEIGHT_SEVERITY,
            "abuseipdb_weight": WEIGHT_ABUSEIPDB,
            "virustotal_weight": WEIGHT_VIRUSTOTAL,
        },
    }
