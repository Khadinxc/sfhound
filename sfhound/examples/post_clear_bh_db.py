"""
BloodHound API:
1. Authenticate
2. Clear database
"""
import sys
import time
import requests
import yaml


CONFIG_PATH = "config.yaml"
FILE_PATH = "../salesforce-opengraph/opengraph_output/graph.json"

session = requests.Session()
with open(CONFIG_PATH, 'r', encoding="utf-8") as f:
    config = yaml.safe_load(f)['bloodhound']
    base_url = config['url']
    username = config['username']
    secret = config['password']

def authenticate():
    """
    Authenticate Function, authenticates to BH api.
    """
    print("[*] Authenticating...")

    url = f"{base_url}/api/v2/login"

    payload = {
        "login_method": "secret",
        "username": username,
        "secret": secret
    }

    r = session.post(url, json=payload, timeout=10)

    if r.status_code != 200:
        print("[!] Authentication failed")
        print(r.text)
        sys.exit(1)

    data = r.json()
    payload = data.get("data", {})  # <- nested response body

    print(f"Data Received: {data}")
    print(f"UserID: {payload.get('user_id')}")
    print(f"Auth Expired: {payload.get('auth_expired')}")
    print(f"Session Token: {payload.get('session_token')}")

    token = payload.get("session_token") or payload.get("token")

    if not token:
        print("[!] No JWT returned")
        print(data)
        sys.exit(1)

    session.headers.update({
        "Authorization": f"Bearer {token}"
    })

    print("[+] Authenticated successfully")


def clear_database():
    """
    Clears Bloodhound Database.
    """
    print("[*] Clearing BloodHound database...")

    url = f"{base_url}/api/v2/clear-database"

    clear_payload = {
        "deleteCollectedGraphData": True,
        "deleteFileIngestHistory": True,
        "deleteDataQualityHistory": True,
        "deleteAssetGroupSelectors": [0],  # or [] if you don't want to delete any selectors
    }

    headers = {
        "Accept": "text/plain",
        "Prefer": "wait=30",
        # Content-Type will be set by requests when using json=...
    }

    r = session.post(url, json=clear_payload, headers=headers, timeout=60)

    if r.status_code != 204:
        print("[!] Database reset failed")
        print(f"Status: {r.status_code}")
        print(r.text)
        sys.exit(1)

    print("[+] Database cleared successfully")
    time.sleep(2)


if __name__ == "__main__":
    authenticate()
    clear_database()
    print("Cleared Database.")
