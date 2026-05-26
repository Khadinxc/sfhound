"""
Create (and optionally delete) bulk PermissionSets in a Salesforce org to
verify that sfhound's queryMore() pagination works correctly.

PermissionSets are used because they can be freely created/deleted without
licence or profile constraints. A unique name prefix tags all test records so
they are easy to identify and clean up.

Usage (from the sfhound/ directory):
    # Create 250 test PermissionSets (2+ pages at 200/page)
    python -m examples.create_test_data

    # Create a custom number
    python -m examples.create_test_data --count 450

    # Verify pagination by querying them back at a given page size
    python -m examples.create_test_data --verify --page-size 200

    # Delete all test records tagged with the prefix
    python -m examples.create_test_data --cleanup

    # Custom config path
    python -m examples.create_test_data --config path/to/config.yaml
"""

import sys
import argparse
import math
import yaml
import requests

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

CONFIG_PATH = "config.yaml"
TEST_PREFIX = "SFHound_Test_"   # prefix on every test PermissionSet Name/Label
BATCH_SIZE  = 200               # Salesforce Collections API max per request


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _load_sf_config(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)["salesforce"]


def _authenticate(cfg: dict) -> tuple[str, str]:
    """Return (access_token, instance_url) using whatever auth type is configured."""
    import time
    auth_type = cfg.get("type", "certificate_and_secret")

    if auth_type == "certificate_and_secret":
        import jwt as pyjwt
        payload = {
            "iss": cfg["client_id"],
            "sub": cfg["username"],
            "aud": cfg["login_url"],
            "exp": int(time.time()) + 300,
        }
        with open(cfg["private_key"], "r") as kf:
            private_key = kf.read()
        assertion = pyjwt.encode(payload, private_key, algorithm="RS256")
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }
    elif auth_type == "client_credential_flow":
        data = {
            "grant_type": "client_credentials",
            "client_id":     cfg["client_id"],
            "client_secret": cfg["client_secret"],
        }
    else:
        print(f"[!] Unknown auth type: {auth_type}")
        sys.exit(1)

    r = requests.post(f"{cfg['login_url']}/services/oauth2/token", data=data, timeout=30)
    if r.status_code != 200:
        print(f"[!] Authentication failed: {r.text}")
        sys.exit(1)

    resp = r.json()
    token        = resp["access_token"]
    instance_url = resp["instance_url"]
    print(f"[+] Authenticated to {instance_url}")
    return token, instance_url


# ---------------------------------------------------------------------------
# Salesforce REST helpers
# ---------------------------------------------------------------------------

def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }


def _soql(token: str, instance_url: str, api_version: str, soql: str,
          page_size: int | None = None) -> list[dict]:
    """Run a SOQL query with full queryMore() pagination."""
    headers = _headers(token)
    if page_size is not None:
        headers["Sforce-Query-Options"] = f"batchSize={page_size}"

    url    = f"{instance_url}/services/data/{api_version}/query"
    params = {"q": soql}
    records = []
    page_num = 0

    while True:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if r.status_code != 200:
            print(f"[!] SOQL failed: {r.text}")
            sys.exit(1)
        data = r.json()
        page_num += 1
        page_records = data.get("records", [])
        records.extend(page_records)
        print(f"    Page {page_num}: {len(page_records)} records (running total: {len(records)})")

        if data.get("done") is True:
            break
        next_url = data.get("nextRecordsUrl")
        if not next_url:
            break
        url    = f"{instance_url}{next_url}"
        params = None

    return records


def _create_batch(token: str, instance_url: str, api_version: str,
                  records: list[dict]) -> list[str]:
    """
    Create up to 200 records via the Collections API.
    Returns a list of created IDs (failures are printed and skipped).
    """
    url = f"{instance_url}/services/data/{api_version}/composite/sobjects"
    body = {"allOrNone": False, "records": records}
    r = requests.post(url, headers=_headers(token), json=body, timeout=60)
    if r.status_code not in (200, 201):
        print(f"[!] Batch create failed: {r.text}")
        sys.exit(1)

    created_ids = []
    for item in r.json():
        if item.get("success"):
            created_ids.append(item["id"])
        else:
            errors = item.get("errors", [])
            print(f"[!] Record failed: {errors}")
    return created_ids


def _delete_batch(token: str, instance_url: str, api_version: str,
                  ids: list[str]) -> None:
    """Delete up to 200 records by ID via the Collections API."""
    ids_param = ",".join(ids)
    url = (
        f"{instance_url}/services/data/{api_version}/composite/sobjects"
        f"?ids={ids_param}&allOrNone=false"
    )
    r = requests.delete(url, headers=_headers(token), timeout=60)
    if r.status_code not in (200, 204):
        print(f"[!] Batch delete failed: {r.text}")
        sys.exit(1)

    for item in r.json():
        if not item.get("success"):
            print(f"[!] Delete failed for {item.get('id')}: {item.get('errors')}")


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def create_records(token: str, instance_url: str, api_version: str, count: int) -> None:
    """Bulk-create `count` test PermissionSets in batches of BATCH_SIZE."""
    print(f"\n[*] Creating {count} test PermissionSets (prefix: '{TEST_PREFIX}') ...")
    total_created = 0
    batches = math.ceil(count / BATCH_SIZE)

    for b in range(batches):
        start = b * BATCH_SIZE
        end   = min(start + BATCH_SIZE, count)
        records = [
            {
                "attributes": {"type": "PermissionSet"},
                "Name":        f"{TEST_PREFIX}{i:04d}",
                "Label":       f"{TEST_PREFIX}{i:04d}",
                "Description": "Temporary sfhound pagination test record — safe to delete",
            }
            for i in range(start, end)
        ]
        created = _create_batch(token, instance_url, api_version, records)
        total_created += len(created)
        print(f"    Batch {b + 1}/{batches}: created {len(created)} records")

    print(f"[+] Done — {total_created}/{count} PermissionSets created.")
    print(f"[!] Run with --cleanup when finished to remove them.")


def verify_pagination(token: str, instance_url: str, api_version: str,
                      page_size: int) -> None:
    """
    Query all test PermissionSets back using the given page size and confirm
    the total matches what exists in the org.
    """
    print(f"\n[*] Verifying pagination (page size: {page_size}) ...")
    soql = (  # nosec B608
        f"SELECT Id, Name FROM PermissionSet "
        f"WHERE Name LIKE '{TEST_PREFIX}%' "
        f"ORDER BY Name"
    )
    print(f"[*] SOQL: {soql}")
    records = _soql(token, instance_url, api_version, soql, page_size=page_size)
    print(f"\n[+] Pagination complete — retrieved {len(records)} records across all pages.")

    if len(records) == 0:
        print("[!] No test records found. Run without --verify first to create them.")


def cleanup(token: str, instance_url: str, api_version: str) -> None:
    """Delete all PermissionSets whose Name starts with TEST_PREFIX."""
    print(f"\n[*] Querying test records to delete (prefix: '{TEST_PREFIX}') ...")
    soql = (  # nosec B608
        f"SELECT Id, Name FROM PermissionSet "
        f"WHERE Name LIKE '{TEST_PREFIX}%'"
    )
    records = _soql(token, instance_url, api_version, soql)
    if not records:
        print("[+] No test records found — nothing to delete.")
        return

    ids = [r["Id"] for r in records]
    print(f"[*] Deleting {len(ids)} records in batches of {BATCH_SIZE} ...")
    batches = math.ceil(len(ids) / BATCH_SIZE)
    for b in range(batches):
        chunk = ids[b * BATCH_SIZE : (b + 1) * BATCH_SIZE]
        _delete_batch(token, instance_url, api_version, chunk)
        print(f"    Batch {b + 1}/{batches}: deleted {len(chunk)} records")

    print(f"[+] Cleanup complete — {len(ids)} records deleted.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Create/verify/delete bulk Salesforce test data for sfhound pagination testing",
    )
    parser.add_argument("--config",    default=CONFIG_PATH, help="Path to config.yaml")
    parser.add_argument("--count",     type=int, default=250,
                        help="Number of PermissionSets to create (default: 250)")
    parser.add_argument("--page-size", type=int, default=200,
                        help="Records per page when --verify is used (default: 200)")
    parser.add_argument("--verify",    action="store_true",
                        help="Query test records back and print per-page counts")
    parser.add_argument("--cleanup",   action="store_true",
                        help="Delete all test records with the test prefix")
    args = parser.parse_args()

    cfg         = _load_sf_config(args.config)
    api_version = cfg.get("api_version", "v56.0")
    token, instance_url = _authenticate(cfg)

    if args.cleanup:
        cleanup(token, instance_url, api_version)
    elif args.verify:
        verify_pagination(token, instance_url, api_version, args.page_size)
    else:
        create_records(token, instance_url, api_version, args.count)


if __name__ == "__main__":
    main()
