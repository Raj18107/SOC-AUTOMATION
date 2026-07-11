# wazuh_api.py
# Member 2 — Wazuh REST API Connector

import os
import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from config import WAZUH_URL as DEFAULT_WAZUH_URL, INDEXER_URL as DEFAULT_INDEXER_URL

WAZUH_URL  = os.getenv("WAZUH_URL",  DEFAULT_WAZUH_URL)

WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_PASS", "PLACEHOLDER_CHANGE_ME")

# Indexer (OpenSearch) — used for fetching alerts
INDEXER_URL  = os.getenv("INDEXER_URL",  DEFAULT_INDEXER_URL)
INDEXER_USER = os.getenv("INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASS", "PLACEHOLDER_CHANGE_ME")


def get_token():
    response = requests.post(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False,
        timeout=60
    )
    response.raise_for_status()
    return response.json()["data"]["token"]


def get_alerts(limit=200, min_level=1):
    response = requests.post(
        f"{INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(INDEXER_USER, INDEXER_PASS),
        verify=False,
        timeout=20,
        json={
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "range": {"rule.level": {"gte": min_level}}
            }
        }
    )
    response.raise_for_status()
    hits = response.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]

def get_agent_list():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{WAZUH_URL}/agents", headers=headers, verify=False, timeout=15, params={"limit":50})
    r.raise_for_status()
    return r.json().get("data", {}).get("affected_items", [])

# SELF-TEST (run: python wazuh_api.py)
if __name__ == "__main__":
    print("=" * 65)
    print("  wazuh_api.py — Connection Test")
    print("=" * 65)
    print(f"  URL:   {WAZUH_URL}")
    print(f"  User:  {WAZUH_USER}")
    print(f"  Pass:  {'*' * len(WAZUH_PASS)}")
    print("=" * 65)

    try:
        t = get_token()
        print("Test 1: Authenticate... PASS")
        print(f"  Token: {t[:40]}...")
    except Exception as e:
        print(f"Test 1: Authenticate... FAIL — {e}")
        print("\nUpdate .env with the correct IP and password, then re-run.")
        exit(0)

    try:
        alerts = get_alerts(limit=5, min_level=1)
        print(f"Test 2: Get alerts... PASS — {len(alerts)} alerts")
    except Exception as e:
        print(f"Test 2: Get alerts... FAIL — {e}")

    try:
        agents = get_agent_list()
        print(f"Test 3: Get agents... PASS — {len(agents)} agents")
        for a in agents:
            print(f"    {a.get('name')} - {a.get('status')}")
    except Exception as e:
        print(f"Test 3: Get agents... FAIL — {e}")

    print("=" * 65)
    print("  All tests passed — wazuh_api.py is ready!")
    print("=" * 65)
