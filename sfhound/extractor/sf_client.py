import yaml
import jwt
import time
import requests
from typing import Dict, Any, List, Optional


class SalesforceClient:
    """
    Salesforce REST + Tooling API client using JWT OAuth flow.
    Reads config from your YAML file.

    Provides:
        query()
        tooling_query()
        describe()
        get()
    """

    def __init__(self, config_path: str):
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)["salesforce"]

        self.client_id = cfg["client_id"]
        self.client_secret = cfg.get("client_secret")
        self.username = cfg["username"]
        self.private_key_path = cfg["private_key"]
        self.login_url = cfg["login_url"]
        self.api_version = cfg.get("api_version", "v56.0")

        self.access_token: Optional[str] = None
        self.instance_url: Optional[str] = None

    # ----------------------------------------
    # AUTHENTICATION
    # ----------------------------------------

    def authenticate(self):
        with open(self.private_key_path, "r", encoding="utf-8") as f:
            private_key = f.read()

        payload = {
            "iss": self.client_id,
            "sub": self.username,
            "aud": self.login_url,
            "exp": int(time.time()) + 300,
        }

        assertion = jwt.encode(payload, private_key, algorithm="RS256")

        url = f"{self.login_url}/services/oauth2/token"

        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }

        r = requests.post(url, data=data, timeout=30)

        if r.status_code != 200:
            raise Exception(f"Salesforce auth failed: {r.text}")

        resp = r.json()

        self.access_token = resp["access_token"]
        self.instance_url = resp["instance_url"]

        print(f"[+] Authenticated to {self.instance_url}")

    # ----------------------------------------
    # LOW LEVEL REST
    # ----------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    def get(self, path: str, params=None) -> Dict[str, Any]:
        url = f"{self.instance_url}/services/data/{self.api_version}{path}"
        r = requests.get(url, headers=self._headers(), params=params, timeout=60)

        if r.status_code != 200:
            raise Exception(r.text)

        return r.json()

    # ----------------------------------------
    # SOQL QUERY WITH PAGINATION
    # ----------------------------------------

    def query(self, soql: str) -> Dict[str, Any]:
        results = {"records": []}
        path = "/query"
        params = {"q": soql}

        while True:
            data = self.get(path, params=params)
            results["records"].extend(data.get("records", []))

            if data.get("done") is True:
                break

            next_url = data.get("nextRecordsUrl")
            if not next_url:
                break

            # nextRecordsUrl is already a full REST path like /services/data/vXX.X/query/01g...
            path = next_url.replace(f"/services/data/{self.api_version}", "")
            params = None

        return results

    # ----------------------------------------
    # TOOLING API QUERY (CRITICAL FOR PERMISSIONS)
    # ----------------------------------------

    def tooling_query(self, soql: str) -> Dict[str, Any]:

        url = f"{self.instance_url}/services/data/{self.api_version}/tooling/query"
        params = {"q": soql}

        all_records = []

        r = requests.get(url, headers=self._headers(), params=params, timeout=60)

        if r.status_code != 200:
            raise Exception(r.text)

        data = r.json()

        all_records.extend(data.get("records", []))

        while not data.get("done", True):

            next_url = data.get("nextRecordsUrl")

            r = requests.get(
                f"{self.instance_url}{next_url}",
                headers=self._headers(),
                timeout=60,
            )

            if r.status_code != 200:
                raise Exception(r.text)

            data = r.json()

            all_records.extend(data.get("records", []))

        return {"records": all_records}

    # ----------------------------------------
    # DESCRIBE OBJECT
    # ----------------------------------------

    def describe(self, object_name: str):

        return self.get(f"/sobjects/{object_name}/describe")
