"""
Publish all Cypher queries from examples/cypher_queries.yaml to BloodHound as
saved queries via the BloodHound CE API (POST /api/v2/saved-queries).

Each query is saved with its name and Cypher text. Queries that already exist
under the same name are skipped unless --overwrite is passed.

Usage (from sf-opengraph/):
    python -m examples.post_cypher_queries
    python -m examples.post_cypher_queries --overwrite
    python -m examples.post_cypher_queries --queries-file path/to/cypher_queries.yaml
"""

import sys
import argparse
import os
import requests
import yaml

CONFIG_PATH = "config.yaml"
DEFAULT_QUERIES_FILE = os.path.join(os.path.dirname(__file__), "cypher_queries.yaml")

session = requests.Session()

with open(CONFIG_PATH, 'r', encoding="utf-8") as f:
    config = yaml.safe_load(f)['bloodhound']
    base_url = config['url']
    username = config['username']
    secret = config['password']


def authenticate():
    """Authenticate to the BloodHound API and attach the session token."""
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
        "Accept": "application/json",
    })

    print("[+] Authenticated successfully")
    return token


def get_existing_saved_queries() -> dict[str, int]:
    """
    Fetch all saved queries already stored in BloodHound.

    Returns:
        dict mapping query name -> query id for every existing saved query.
    """
    url = f"{base_url}/api/v2/saved-queries"
    existing: dict[str, int] = {}
    skip = 0
    limit = 100

    while True:
        r = session.get(url, params={"skip": skip, "limit": limit}, timeout=15)
        if r.status_code != 200:
            print(f"[!] Failed to list existing saved queries (HTTP {r.status_code})")
            print(r.text)
            break

        data = r.json()
        items = (data.get("data") or data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            items = []

        for item in items:
            name = item.get("name") or item.get("query_name", "")
            qid = item.get("id")
            if name and qid is not None:
                existing[name] = qid

        if len(items) < limit:
            break
        skip += limit

    return existing


def delete_saved_query(query_id: int, name: str) -> bool:
    """Delete a saved query by id (used when --overwrite is set)."""
    url = f"{base_url}/api/v2/saved-queries/{query_id}"
    r = session.delete(url, timeout=10)
    if r.status_code in (200, 204):
        print(f"    [~] Deleted existing query '{name}' (id={query_id})")
        return True
    print(f"    [!] Failed to delete existing query '{name}' (HTTP {r.status_code}): {r.text}")
    return False


def publish_query(name: str, query: str, overwrite: bool, existing: dict[str, int]) -> bool:
    """
    Create a saved query in BloodHound.

    Args:
        name:      Display name for the saved query.
        query:     Cypher query string.
        overwrite: If True and the query already exists, delete it first.
        existing:  Map of name -> id for already-stored queries.

    Returns:
        True on success, False on failure.
    """
    if name in existing:
        if not overwrite:
            print(f"  [~] Skipping '{name}' — already exists (use --overwrite to replace)")
            return True
        if not delete_saved_query(existing[name], name):
            return False

    url = f"{base_url}/api/v2/saved-queries"
    payload = {
        "name": name,
        "query": query.strip(),
    }

    r = session.post(url, json=payload, timeout=15)

    if r.status_code in (200, 201):
        try:
            resp_data = r.json()
            saved = resp_data.get("data") or resp_data
            qid = saved.get("id") if isinstance(saved, dict) else None
            print(f"  [+] Published '{name}'" + (f" (id={qid})" if qid else ""))
        except Exception:
            print(f"  [+] Published '{name}'")
        return True

    print(f"  [!] Failed to publish '{name}' (HTTP {r.status_code}): {r.text}")
    return False


def load_queries(queries_file: str) -> list[dict]:
    """Load and validate the query list from a YAML file."""
    if not os.path.isfile(queries_file):
        print(f"[!] Queries file not found: {queries_file}")
        sys.exit(1)

    with open(queries_file, 'r', encoding="utf-8") as f:
        data = yaml.safe_load(f)

    queries = data.get("queries", [])
    if not queries:
        print("[!] No queries found in the YAML file.")
        sys.exit(1)

    return queries


# ---- MAIN ----

def main():
    parser = argparse.ArgumentParser(
        description="Publish SFHound Cypher queries to BloodHound as saved queries."
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Delete and re-create queries that already exist in BloodHound.",
    )
    parser.add_argument(
        "--queries-file",
        default=DEFAULT_QUERIES_FILE,
        metavar="PATH",
        help=f"Path to the YAML file containing queries (default: {DEFAULT_QUERIES_FILE})",
    )
    parser.add_argument(
        "--category",
        default=None,
        metavar="CATEGORY",
        help="Only publish queries belonging to this category (e.g. tier_zero, system_permissions).",
    )
    args = parser.parse_args()

    queries = load_queries(args.queries_file)

    if args.category:
        queries = [q for q in queries if q.get("category") == args.category]
        if not queries:
            print(f"[!] No queries found for category '{args.category}'.")
            sys.exit(1)
        print(f"[*] Filtered to {len(queries)} queries in category '{args.category}'")

    authenticate()

    print(f"\n[*] Fetching existing saved queries from BloodHound...")
    existing = get_existing_saved_queries()
    print(f"[*] Found {len(existing)} existing saved queries")

    print(f"\n[*] Publishing {len(queries)} queries from {args.queries_file}\n")

    success = 0
    failed = 0

    categories_seen: list[str] = []
    for entry in queries:
        name = entry.get("name", "").strip()
        query = entry.get("query", "").strip()
        category = entry.get("category", "uncategorized")

        if not name or not query:
            print(f"  [!] Skipping entry with missing name or query: {entry}")
            failed += 1
            continue

        if category not in categories_seen:
            categories_seen.append(category)
            print(f"--- {category.replace('_', ' ').title()} ---")

        if publish_query(name, query, args.overwrite, existing):
            success += 1
        else:
            failed += 1

    print(f"\n[*] Done — {success} published, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
