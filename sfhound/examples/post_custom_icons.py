"""
Python script to authenticate and update Custom Icons for Salesforce Ingestion in Bloodhound.
"""
import sys
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

session = requests.Session()


def authenticate():
    """
    Authenticate Function, authenticates to BH api.
    """
    print("[*] Authenticating...")

    url = f"{base_url}/api/v2/login"
    payload = {
        "login_method": "secret",
        "username": username,
        "secret": secret,
    }

    r = session.post(url, json=payload, timeout=10)
    if r.status_code != 200:
        print("[!] Authentication failed")
        print(r.text)
        sys.exit(1)

    data = r.json()

    token = (
        data.get("session_token")
        or data.get("token")
        or (data.get("data") or {}).get("session_token")
        or (data.get("data") or {}).get("token")
    )

    if not token:
        print("[!] No JWT returned")
        print(data)
        sys.exit(1)

    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })

    print("[+] Authenticated successfully")
    return token


def set_icon(kind: str, fa_name: str, color: str | None = None):
    """
    Function to set icons after authentication in Bloodhound via the API.
    """
    payload = {
        "custom_types": {
            kind: {
                "icon": {
                    "type": "font-awesome",
                    "name": fa_name,
                }
            }
        }
    }
    if color:
        payload["custom_types"][kind]["icon"]["color"] = color

    url = f"{base_url}/api/v2/custom-nodes"
    r = session.post(url, json=payload, timeout=30)

    # Success = any 2xx
    if 200 <= r.status_code < 300:
        try:
            print(f"[+] Set icon for {kind}: {r.json()}")
        except Exception:
            print(f"[+] Set icon for {kind} (no JSON body)")
        return

    print(f"[!] Failed setting icon for {kind} (HTTP {r.status_code})")
    print(r.text)


# ---- RUN ----

authenticate()

set_icon("SFUser", "user", "#00b894")
set_icon("SFProfile", "user-gear", "#0984e3")
set_icon("SFPermissionSet", "id-badge", "#7f8c8d")
set_icon("SFRole", "sitemap", "#6c5ce7")
set_icon("SFGroup", "users", "#fdcb6e")
set_icon("SFPermissionSetGroup", "users", "#fdcb6e")
set_icon("SFQueue", "inbox", "#e17055")
set_icon("SFConnectedApp", "plug", "#00cec9")
set_icon("SFSObject", "database", "#636e72")
set_icon("SFObjectPermission", "key", "#d63031")
set_icon("SFField", "list-check", "#e84393")
set_icon("SFOrganization", "building", "#2d3436")  # Organization node (system permissions are edges to this)
set_icon("SFSharingRule", "share-nodes", "#fd79a8")
