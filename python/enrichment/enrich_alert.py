#!/usr/bin/env python3
"""
enrich_alert.py
----------------
Identity‑focused alert enrichment demo.

• Reads configuration from environment variables.
• Enriches minimal alerts with mock identity details (Okta‑like),
  optional GeoIP data, and a more realistic identity‑centric risk score.

Environment variables you can set:
  OKTA_API_URL=https://dev-12345.okta.com
  OKTA_API_TOKEN=example_token
  GEOIP_API_KEY=example_geo_key
  ENV=dev|prod
"""

import os
import random
import time
from typing import Dict, Any, Optional
import requests


# -----------------------------------------------------------------------------
# Configuration helpers
# -----------------------------------------------------------------------------

def get_env_var(name: str, default: Optional[str] = None) -> str:
    """Fetch an environment variable or a default."""
    val = os.getenv(name, default)
    if val is None:
        raise RuntimeError(f"Required environment variable '{name}' not set")
    return val


API_CONFIG = {
    "okta_url": get_env_var("OKTA_API_URL", "https://demo.okta.com"),
    "okta_token": get_env_var("OKTA_API_TOKEN", "dummy_token"),
    "geoip_key": os.getenv("GEOIP_API_KEY", ""),
    "env": os.getenv("ENV", "dev")
}

# -----------------------------------------------------------------------------
# Mockable API clients — these can easily be replaced by real calls.
# -----------------------------------------------------------------------------

def get_identity_from_okta(user_id: str) -> Dict[str, Any]:
    """
    Simulates fetching identity attributes from Okta.
    In a production variant, this would call:
      GET {OKTA_API_URL}/api/v1/users/{user_id}
    with the authorization header: Bearer {OKTA_API_TOKEN}
    """
    # Example placeholder
    try:
        # If demoing real API, uncomment and adjust:
        # resp = requests.get(f"{API_CONFIG['okta_url']}/api/v1/users/{user_id}",
        #                     headers={"Authorization": f"SSWS {API_CONFIG['okta_token']}"})
        # resp.raise_for_status()
        # return resp.json()
        departments = ["Security", "Engineering", "Finance", "HR"]
        mfa_enabled = random.choice([True, False])
        return {
            "user_id": user_id,
            "email": f"{user_id}@example.com",
            "department": random.choice(departments),
            "status": random.choice(["ACTIVE", "SUSPENDED", "DEPROVISIONED"]),
            "mfa_enabled": mfa_enabled,
            "last_login": int(time.time()) - random.randint(0, 86400 * 30),
        }
    except requests.RequestException as e:
        return {"error": str(e), "user_id": user_id}


def get_geoip_info(ip: str) -> Dict[str, Any]:
    """
    Simulates or performs GeoIP lookup.
    Replace with an actual call if GEOIP_API_KEY present.
    """
    if not API_CONFIG["geoip_key"]:
        # local pseudo‑lookup
        cities = ["London", "New York", "Paris", "Tokyo"]
        countries = ["UK", "US", "FR", "JP"]
        i = random.randint(0, len(cities) - 1)
        return {"ip": ip, "city": cities[i], "country": countries[i]}

    try:
        resp = requests.get(
            f"https://api.ipgeolocation.io/ipgeo?apiKey={API_CONFIG['geoip_key']}&ip={ip}",
            timeout=5)
        resp.raise_for_status()
        data = resp.json()
        return {"ip": ip, "city": data.get("city"), "country": data.get("country_name")}
    except requests.RequestException as e:
        return {"ip": ip, "error": str(e)}


# -----------------------------------------------------------------------------
# Risk scoring
# -----------------------------------------------------------------------------

def calculate_identity_risk(user: Dict[str, Any],
                            geo: Optional[Dict[str, Any]] = None) -> int:
    """
    Compute a basic identity risk score:
      - Suspended or deprovisioned accounts: +60
      - MFA disabled: +20
      - Unusual geo (not US/UK): +20
    Max score 100
    """
    score = 0

    if user.get("status") in ["SUSPENDED", "DEPROVISIONED"]:
        score += 60

    if not user.get("mfa_enabled", True):
        score += 20

    if geo and geo.get("country") not in ("US", "UK"):
        score += 20

    return min(score, 100)


# -----------------------------------------------------------------------------
# Main enrichment function
# -----------------------------------------------------------------------------

def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Takes a minimal alert (user_id, src_ip, ...),
    returns enriched alert with identity + geo context + risk score.
    """

    user_id = alert.get("user_id")
    src_ip = alert.get("src_ip")

    identity_data = get_identity_from_okta(user_id)
    geo_data = get_geoip_info(src_ip) if src_ip else {}
    risk_score = calculate_identity_risk(identity_data, geo_data)

    enriched = {
        **alert,
        "user_email": identity_data.get("email"),
        "user_department": identity_data.get("department"),
        "user_status": identity_data.get("status"),
        "mfa_enabled": identity_data.get("mfa_enabled"),
        "last_login": identity_data.get("last_login"),
        "geo_country": geo_data.get("country"),
        "geo_city": geo_data.get("city"),
        "risk_score": risk_score,
        "enrichment_env": API_CONFIG["env"]
    }

    return enriched


# -----------------------------------------------------------------------------
# CLI Demo
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    sample_alert = {
        "alert_id": "aa-001",
        "user_id": "alice",
        "src_ip": "8.8.8.8",
        "hostname": "ip-10-0-5-12",
        "timestamp": int(time.time())
    }

    enriched = enrich_alert(sample_alert)

    print("Original alert:")
    print(sample_alert)
    print("\nEnriched alert:")
    for k, v in enriched.items():
        print(f"{k:20s}: {v}")
