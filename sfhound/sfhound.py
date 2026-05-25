"""
sfhound.py, the bones of the operation. Sniffing sales so you don't have to.
All the work happens in this module wiring all the supporting functions together.
"""
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse
import yaml
import argparse

from .extractor.auth import SalesforceAuth
from .extractor.metadata import MetadataExtractor
from .extractor.assignments import AssignmentExtractor

from .graph.nodes import NodeBuilder, make_node
from .graph.edges import EdgeBuilder
from .graph.sfgraph import SFGraph
from .bloodhound_api import BloodHoundAPI

CONFIG_PATH = "config.yaml"

# ---------------------------------------------------------------------------
# Scope constants
# ---------------------------------------------------------------------------

VALID_SCOPES = frozenset({
    "users", "groups", "queues", "profiles",
    "permissionsets", "roles", "connectedapps", "objects", "fields",
})

# Node kinds that belong to each scope (used to filter nodes at export time).
SCOPE_NODE_KINDS = {
    "users":          frozenset(["SFUser"]),
    "groups":         frozenset(["SFGroup", "SFPublicGroup"]),
    "queues":         frozenset(["SFQueue"]),
    "profiles":       frozenset(["SFProfile", "SFOrganization"]),
    "permissionsets": frozenset(["SFPermissionSet", "SFPermissionSetGroup", "SFOrganization"]),
    "roles":          frozenset(["SFRole"]),
    "connectedapps":  frozenset(["SFConnectedApp"]),
    "objects":        frozenset(["SFSObject"]),
    "fields":         frozenset(["SFField"]),
}

# Metadata extractor methods needed per scope.
SCOPE_METADATA_EXTRACTORS = {
    "users":          frozenset(),
    "groups":         frozenset(["extract_groups"]),
    "queues":         frozenset(["extract_groups", "extract_queue_sobjects", "extract_sobjects"]),
    "profiles":       frozenset(["extract_profiles", "extract_permission_sets",
                                  "extract_setup_entity_access"]),
    "permissionsets": frozenset(["extract_permission_sets", "extract_permission_set_groups",
                                  "extract_permission_set_group_components",
                                  "extract_setup_entity_access"]),
    "roles":          frozenset(["extract_user_roles"]),
    "connectedapps":  frozenset(["extract_connected_apps"]),
    "objects":        frozenset(["extract_sobjects", "extract_object_permissions"]),
    "fields":         frozenset(["extract_field_permissions"]),
}

# Assignment extractor methods needed per scope.
SCOPE_ASSIGNMENT_EXTRACTORS = {
    "users":          frozenset(["extract_users", "extract_permission_set_assignments",
                                  "extract_permission_set_group_assignments",
                                  "extract_group_members"]),
    "groups":         frozenset(["extract_group_members"]),
    "queues":         frozenset(["extract_group_members"]),
    "profiles":       frozenset(),
    "permissionsets": frozenset(["extract_permission_set_assignments",
                                  "extract_permission_set_group_assignments"]),
    "roles":          frozenset(),
    "connectedapps":  frozenset(),
    "objects":        frozenset(),
    "fields":         frozenset(),
}

# Scopes that require extract_record_owners (which also needs extract_sobjects).
_SCOPE_NEEDS_RECORD_OWNERS = frozenset(["users"])

# Canonical execution order for all metadata extractors.
_ALL_METADATA_EXTRACTORS = [
    "extract_profiles",
    "extract_permission_sets",
    "extract_groups",
    "extract_permission_set_groups",
    "extract_permission_set_group_components",
    "extract_user_roles",
    "extract_queue_sobjects",
    "extract_connected_apps",
    "extract_setup_entity_access",
    "extract_sobjects",
    "extract_object_permissions",
    "extract_field_permissions",
]

# Canonical execution order for all assignment extractors.
_ALL_ASSIGNMENT_EXTRACTORS = [
    "extract_users",
    "extract_permission_set_assignments",
    "extract_group_members",
    "extract_permission_set_group_assignments",
]

# Edge kinds whose scope is determined by their semantic target, not start-node kind.
# CRUD/FLS permissions belong to 'objects'/'fields' even when starting from Profile/PermSet.
_OBJECT_EDGE_KINDS = frozenset({
    "SF_CanCreate", "SF_CanRead", "SF_CanEdit", "SF_CanDelete",
    "SF_CanViewAll", "SF_CanModifyAll",
})
_FIELD_EDGE_KINDS = frozenset({
    "SF_IsVisible", "SF_ReadOnly",
})

# Node kind → scope name, used to assign edges based on their start node type.
_KIND_TO_SCOPE = {
    "SFUser":               "users",
    "SFProfile":            "profiles",
    "SFPermissionSet":      "permissionsets",
    "SFPermissionSetGroup": "permissionsets",
    "SFRole":               "roles",
    "SFGroup":              "groups",
    "SFPublicGroup":        "groups",
    "SFQueue":              "queues",
    "SFConnectedApp":       "connectedapps",
}


def parse_arguments():
    """Parse command-line arguments to override config.yaml values."""
    parser = argparse.ArgumentParser(
        description="SFHound - Six Degrees of System Administrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Full collection — one output file (default behaviour)
  sfhound

  # Selective collection — one file per scope
  sfhound -s users,groups
  sfhound -s objects,profiles,permissionsets

  # Override credentials
  sfhound --client-id YOUR_ID --username user@example.com

  # Throttled mode for large orgs
  sfhound --throttle 200 -v

  # Sandbox org
  sfhound --login-url https://test.salesforce.com --verbose

Valid --scope values: {', '.join(sorted(VALID_SCOPES))}
        """
    )
    
    # Config file
    parser.add_argument(
        "--config",
        default=CONFIG_PATH,
        help=f"Path to config YAML file (default: {CONFIG_PATH})"
    )
    
    # Salesforce connection settings
    sf_group = parser.add_argument_group("Salesforce connection")
    sf_group.add_argument("--auth-type", choices=['certificate_and_secret', 'client_credential_flow'],
                          help="Auth flow: 'certificate_and_secret' (JWT Bearer, requires private-key) "
                               "or 'client_credential_flow' (OAuth 2.0 client credentials, requires client-secret)")
    sf_group.add_argument("--client-id", help="Salesforce Connected App Client ID")
    sf_group.add_argument("--client-secret", help="Salesforce Connected App Client Secret")
    sf_group.add_argument("--username", help="Salesforce username")
    sf_group.add_argument("--private-key", help="Path to private key file for JWT authentication")
    sf_group.add_argument("--login-url", help="Salesforce login URL (default: https://login.salesforce.com)")
    sf_group.add_argument("--api-version", help="Salesforce API version (default: v56.0)")
    
    # Output settings
    output_group = parser.add_argument_group("Output settings")
    output_group.add_argument("--output-path", help="Directory for output JSON files (default: ./opengraph_output)")

    # Extraction settings
    extract_group = parser.add_argument_group("Extraction settings")
    extract_group.add_argument(
        "-s", "--scope",
        default=None,
        metavar="SCOPE[,SCOPE...]",
        help=(
            "Collect only the specified node type(s) and write one file per scope. "
            "Without this flag all data is collected into a single output file. "
            f"Valid values (comma-separated): {', '.join(sorted(VALID_SCOPES))}. "
            "Example: -s users,groups,profiles"
        ),
    )
    extract_group.add_argument(
        "-r", "--throttle",
        nargs="?",
        const=200,
        type=int,
        default=None,
        metavar="LIMIT",
        help="Throttled mode: fetch one page per query without queryMore(). "
             "Appends LIMIT <n> to all SOQL queries (default 200 when -r is given without a value).",
    )
    extract_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Print per-query progress and record counts during extraction.",
    )
    extract_group.add_argument(
        "-f", "--fields",
        nargs="?",
        const="all",
        default="all",
        metavar="FILTER",
        help="Field permission filter. "
             "'all' (default): collect all field permissions. "
             "'none': skip field permission collection entirely. "
             "Comma-separated field API names to collect only those fields "
             "(e.g. -f Account.Industry,Contact.Email).",
    )

    # BloodHound CE integration
    bh_group = parser.add_argument_group("BloodHound CE integration")
    bh_group.add_argument("--auto-ingest", action="store_true", default=None,
                          help="Clear the BloodHound database and upload the graph after export "
                               "(not supported with --scope)")
    bh_group.add_argument("--bh-url", metavar="URL",
                          help="BloodHound CE base URL (default: http://127.0.0.1:8080)")
    bh_group.add_argument("--bh-username", metavar="USER",
                          help="BloodHound CE admin username")
    bh_group.add_argument("--bh-password", metavar="PASS",
                          help="BloodHound CE admin password")

    return parser.parse_args()


def load_config(args):
    """
    Load configuration from YAML file and merge with command-line arguments.
    CLI arguments take precedence over config file values.
    """
    # Load base config from file
    config_path = args.config
    if not os.path.exists(config_path):
        print(f"[!] Error: Config file not found: {config_path}")
        print(f"[!] Copy config.yaml.example to {config_path} and configure it.")
        sys.exit(1)
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    # Override with CLI arguments (if provided)
    if args.auth_type:
        config.setdefault('salesforce', {})['type'] = args.auth_type
    if args.client_id:
        config.setdefault('salesforce', {})['client_id'] = args.client_id
    if args.client_secret:
        config.setdefault('salesforce', {})['client_secret'] = args.client_secret
    if args.username:
        config.setdefault('salesforce', {})['username'] = args.username
    if args.private_key:
        config.setdefault('salesforce', {})['private_key'] = args.private_key
    if args.login_url:
        config.setdefault('salesforce', {})['login_url'] = args.login_url
    if args.api_version:
        config.setdefault('salesforce', {})['api_version'] = args.api_version
    if args.output_path:
        config.setdefault('env', {})['output_path'] = args.output_path

    # BloodHound CLI overrides
    if args.auto_ingest:
        config.setdefault('bloodhound', {})['auto-ingest'] = True
    if args.bh_url:
        config.setdefault('bloodhound', {})['url'] = args.bh_url
    if args.bh_username:
        config.setdefault('bloodhound', {})['username'] = args.bh_username
    if args.bh_password:
        config.setdefault('bloodhound', {})['password'] = args.bh_password

    # Validate BloodHound credentials when auto-ingest is enabled
    bh_cfg = config.get('bloodhound', {})
    if bh_cfg.get('auto-ingest'):
        bh_required = ['url', 'username', 'password']
        bh_missing = [f for f in bh_required if not bh_cfg.get(f)]
        if bh_missing:
            print(f"[!] Error: --auto-ingest requires BloodHound credentials. "
                  f"Missing: {', '.join(bh_missing)}")
            print(f"[!] Set them in {config_path} under 'bloodhound:' or via "
                  f"--bh-url / --bh-username / --bh-password")
            sys.exit(1)

    # Validate required fields based on auth type
    sf_config = config.get('salesforce', {})
    auth_type = sf_config.get('type', 'certificate_and_secret')

    if auth_type == 'certificate_and_secret':
        required = ['client_id', 'username', 'private_key', 'login_url']
    elif auth_type == 'client_credential_flow':
        required = ['client_id', 'client_secret', 'login_url']
    else:
        print(f"[!] Error: Unknown auth type '{auth_type}'. Valid options: certificate_and_secret, client_credential_flow")
        sys.exit(1)

    missing = [field for field in required if not sf_config.get(field)]
    if missing:
        print(f"[!] Error: Missing required Salesforce configuration fields for '{auth_type}': {', '.join(missing)}")
        print(f"[!] Provide them in {config_path} or via CLI arguments (--help for details)")
        sys.exit(1)
    
    return config


def hydrate_missing_profiles(metadata_extractor: MetadataExtractor, users: dict, profiles: dict) -> dict:
    """
    Ensure every ProfileId referenced by Users has a Profile record in `profiles`.

    Some special SF users (e.g. Automated Process / integration users) can reference
    ProfileIds that are not queryable/retrievable via SOQL/REST in the current context.
    For those, we create a synthetic Profile record so the graph remains connected and readable.
    """
    have = {p.get("Id") for p in profiles.get("records", []) if p.get("Id")}
    need = {u.get("ProfileId") for u in users.get("records", []) if u.get("ProfileId")}
    missing = sorted(need - have)

    if not missing:
        return profiles

    # Build a reverse index so we can pick a sensible name for synthetic profiles
    users_by_profile = {}
    for u in users.get("records", []) or []:
        pid = u.get("ProfileId")
        if not pid:
            continue
        users_by_profile.setdefault(pid, []).append(u)

    batch_size = 100
    merged_records = list(profiles.get("records", []))

    fetched_ids = set()

    for i in range(0, len(missing), batch_size):
        chunk = missing[i : i + batch_size]
        quoted = ",".join([f"'{pid}'" for pid in chunk])

        # Keep this minimal and "safe" (Profile fields can vary by API/context)
        soql = f"SELECT Id, Name, UserLicenseId, Description, CreatedDate, LastModifiedDate, SystemModstamp FROM Profile WHERE Id IN ({quoted})"  # nosec B608
        extra = metadata_extractor.query(soql)
        extra_records = extra.get("records", []) or []
        merged_records.extend(extra_records)

        for r in extra_records:
            if r.get("Id"):
                fetched_ids.add(r["Id"])

    # Anything still missing after SOQL hydration becomes synthetic
    still_missing = [pid for pid in missing if pid not in fetched_ids]

    for pid in still_missing:
        sample_users = users_by_profile.get(pid, [])
        # Try to create a human-readable name from the first referencing user
        hint = None
        if sample_users:
            u0 = sample_users[0]
            hint = u0.get("UserType") or u0.get("Username") or u0.get("Name")

        merged_records.append(
            {
                "Id": pid,
                "Name": f"Unresolvable Profile ({hint})" if hint else f"Unresolvable Profile ({pid})",
                "Description": "Synthetic Profile node created by collector: ProfileId referenced by User but Profile not retrievable via API.",
                "IsSynthetic": True,
            }
        )

    return {"records": merged_records}


def add_placeholder_profiles_for_users(users: dict, profiles: dict, graph: "SFGraph") -> None:
    """
    As a final safety net: if Users reference ProfileIds we still don't have
    (API visibility, extraction issues), emit placeholder Profile nodes so
    AssignedProfile edges don't dangle.
    """
    have = {p.get("Id") for p in profiles.get("records", []) if p.get("Id")}
    need = {u.get("ProfileId") for u in users.get("records", []) if u.get("ProfileId")}
    missing = sorted(need - have)

    if not missing:
        return

    for pid in missing:
        graph.add_or_merge_node(
            make_node(pid, ["SFProfile"], {"name": pid, "missing": True})
        )

    print(f"[!] Added {len(missing)} placeholder Profile nodes to prevent dangling edges.")


def build_output_dir(config: dict) -> tuple:
    """Return (base_output_dir, org_subdomain, timestamp) for output file naming."""
    login_url = config["salesforce"]["login_url"]
    base_output_dir = config.get("env", {}).get("output_path", "./opengraph_output")
    os.makedirs(base_output_dir, exist_ok=True)
    parsed = urlparse(login_url)
    hostname = parsed.hostname or "unknown"
    org_subdomain = hostname.split(".")[0]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return base_output_dir, org_subdomain, timestamp


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------

def _parse_scopes(scope_arg):
    """Parse and validate the --scope argument. Returns frozenset or None."""
    if not scope_arg:
        return None
    requested = frozenset(s.strip().lower() for s in scope_arg.split(",") if s.strip())
    unknown = requested - VALID_SCOPES
    if unknown:
        print(f"[!] Unknown scope value(s): {', '.join(sorted(unknown))}")
        print(f"[!] Valid scopes: {', '.join(sorted(VALID_SCOPES))}")
        sys.exit(1)
    if not requested:
        print("[!] --scope requires at least one value")
        sys.exit(1)
    return requested


def _edge_scope(edge_kind, start_node):
    """
    Determine which scope an edge belongs to.

    CRUD and FLS permission edges are assigned to 'objects'/'fields' regardless
    of their start-node kind (Profile or PermSet). All other edges are assigned
    based on the kind of their start node.
    """
    if edge_kind in _OBJECT_EDGE_KINDS:
        return "objects"
    if edge_kind in _FIELD_EDGE_KINDS:
        return "fields"
    if start_node is None:
        return None
    for kind in start_node.kinds:
        if kind in _KIND_TO_SCOPE:
            return _KIND_TO_SCOPE[kind]
    return None


def _export_scope(scope, graph, scope_edges, base_dir, org_subdomain, timestamp):
    """Export a scope-filtered graph to its own output file."""
    scope_kind_set = SCOPE_NODE_KINDS[scope]
    scoped_graph = SFGraph()
    for node_id, node in graph.nodes.items():
        if any(k in scope_kind_set for k in node.kinds):
            scoped_graph.add_node_without_validation(node)
    for edge in scope_edges:
        scoped_graph.add_edge_without_validation(edge)
    output_path = os.path.join(base_dir, f"{org_subdomain}_{timestamp}_{scope}.json")
    scoped_graph.export_to_file(output_path, include_metadata=False, indent=2)
    print(f"[+] Scope '{scope}': {len(scoped_graph.nodes):,} nodes, "
          f"{len(scope_edges):,} edges -> {output_path}")


# ---------------------------------------------------------------------------
# Parallel extraction
# ---------------------------------------------------------------------------

def _parallel_extract(jobs, verbose=False):
    """
    Run a list of (name, callable) extraction jobs concurrently (max 4 workers).

    Returns {name: result}. A job that raises an exception returns {"records": []}.
    Salesforce REST calls are stateless so ThreadPoolExecutor is safe here.
    """
    EMPTY = {"records": []}
    results = {}
    if not jobs:
        return results
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_name = {executor.submit(fn): name for name, fn in jobs}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
                results[name] = result
                if verbose:
                    count = (len(result.get("records", [])) if isinstance(result, dict)
                             else len(result))
                    print(f"  [+] {name}: {count:,} records")
            except Exception as exc:
                print(f"[!] Extractor '{name}' failed: {exc}")
                results[name] = EMPTY
    return results


def main():
    """Main graph export function."""
    args = parse_arguments()
    config = load_config(args)
    throttle = args.throttle
    verbose = args.verbose
    fields_filter = args.fields

    active_scopes = _parse_scopes(args.scope)

    base_dir, org_subdomain, timestamp = build_output_dir(config)

    auth = SalesforceAuth(config)
    auth.authenticate()

    if throttle is not None:
        print(f"[~] Throttled mode enabled: LIMIT {throttle} per query, queryMore() disabled")
    if active_scopes:
        print(f"[~] Scope mode: {', '.join(sorted(active_scopes))}")

    # ------------------------------------------------------------------
    # Determine which extractors to run
    # ------------------------------------------------------------------
    EMPTY = {"records": []}

    metadata_extractor = MetadataExtractor(auth, throttle=throttle)
    assignment_extractor = AssignmentExtractor(auth, throttle=throttle)

    if active_scopes:
        needed_meta   = set().union(*(SCOPE_METADATA_EXTRACTORS[s]  for s in active_scopes))
        needed_assign = set().union(*(SCOPE_ASSIGNMENT_EXTRACTORS[s] for s in active_scopes))
        need_record_owners = bool(active_scopes & _SCOPE_NEEDS_RECORD_OWNERS)
        if need_record_owners:
            needed_meta.add("extract_sobjects")
    else:
        needed_meta   = set(_ALL_METADATA_EXTRACTORS)
        needed_assign = set(_ALL_ASSIGNMENT_EXTRACTORS)
        need_record_owners = True

    # ------------------------------------------------------------------
    # Phase 1 — Metadata extraction (parallel)
    # ------------------------------------------------------------------
    def _field_perm_fn():
        return metadata_extractor.extract_field_permissions(fields_filter)

    meta_jobs = []
    for name in _ALL_METADATA_EXTRACTORS:
        if name not in needed_meta:
            continue
        fn = _field_perm_fn if name == "extract_field_permissions" else getattr(metadata_extractor, name)
        meta_jobs.append((name, fn))

    if verbose:
        print(f"[*] Phase 1 — Metadata extraction ({len(meta_jobs)} queries in parallel)")
    meta_results = _parallel_extract(meta_jobs, verbose=verbose)

    profiles                        = meta_results.get("extract_profiles",                        EMPTY)
    permission_sets                 = meta_results.get("extract_permission_sets",                 EMPTY)
    groups                          = meta_results.get("extract_groups",                          EMPTY)
    permission_set_groups           = meta_results.get("extract_permission_set_groups",           EMPTY)
    permission_set_group_components = meta_results.get("extract_permission_set_group_components", EMPTY)
    user_roles                      = meta_results.get("extract_user_roles",                      EMPTY)
    queue_sobjects                  = meta_results.get("extract_queue_sobjects",                  EMPTY)
    connected_apps                  = meta_results.get("extract_connected_apps",                  EMPTY)
    setup_entity_access             = meta_results.get("extract_setup_entity_access",             EMPTY)
    sobjects                        = meta_results.get("extract_sobjects",                        EMPTY)
    object_permissions              = meta_results.get("extract_object_permissions",              EMPTY)
    field_permissions               = meta_results.get("extract_field_permissions",               EMPTY)

    # ------------------------------------------------------------------
    # Phase 2 — Assignment extraction (parallel)
    # ------------------------------------------------------------------
    assign_jobs = [
        (name, getattr(assignment_extractor, name))
        for name in _ALL_ASSIGNMENT_EXTRACTORS if name in needed_assign
    ]

    if verbose:
        print(f"[*] Phase 2 — Assignment extraction ({len(assign_jobs)} queries in parallel)")
    assign_results = _parallel_extract(assign_jobs, verbose=verbose)

    users                            = assign_results.get("extract_users",                            EMPTY)
    permission_set_assignments       = assign_results.get("extract_permission_set_assignments",       EMPTY)
    group_members                    = assign_results.get("extract_group_members",                    EMPTY)
    permission_set_group_assignments = assign_results.get("extract_permission_set_group_assignments", EMPTY)

    # ------------------------------------------------------------------
    # Record owners — sequential, depends on sobjects from Phase 1
    # ------------------------------------------------------------------
    if need_record_owners and sobjects.get("records"):
        if verbose:
            print("[*] Extracting record owners (parallel across custom objects)...")
        record_owners = assignment_extractor.extract_record_owners(sobjects)
        if verbose:
            print(f"  [+] record owners: {len(record_owners):,} records")
    else:
        record_owners = []

    # ------------------------------------------------------------------
    # Hydrate missing profiles (full-collection mode only)
    # ------------------------------------------------------------------
    if not active_scopes:
        profiles = hydrate_missing_profiles(metadata_extractor, users, profiles)

    # ------------------------------------------------------------------
    # Build nodes
    # ------------------------------------------------------------------
    node_builder = NodeBuilder()
    graph = SFGraph()

    org_node = node_builder.build_organization(auth.instance_url)
    org_node_id = org_node.id
    graph.add_or_merge_node(org_node)

    for node in node_builder.build_users(users):
        graph.add_or_merge_node(node)
    for node in node_builder.build_profiles(profiles):
        graph.add_or_merge_node(node)
    for node in node_builder.build_permission_sets(permission_sets):
        graph.add_or_merge_node(node)
    for node in node_builder.build_roles(user_roles):
        graph.add_or_merge_node(node)

    # Hydrate aggregate/system PermissionSet placeholders (full-collection mode only)
    if not active_scopes:
        _ps_node_ids = {
            nid for nid, n in graph.nodes.items()
            if any(k in ("SFPermissionSet", "SFProfile") for k in n.kinds)
        }
        _ps_parent_map = {}
        for _perm in (*object_permissions.get("records", []), *field_permissions.get("records", [])):
            _pid = _perm.get("ParentId")
            if _pid:
                _ps_parent_map[_pid.strip().upper()] = _pid
        _missing_ps = {orig for norm, orig in _ps_parent_map.items() if norm not in _ps_node_ids}
        if _missing_ps:
            _placeholder_ps = {
                "records": [{"Id": pid, "Name": f"[AggregatePermSet] {pid}"} for pid in _missing_ps]
            }
            for node in node_builder.build_permission_sets(_placeholder_ps):
                graph.add_or_merge_node(node)
            print(f"[+] Hydrated {len(_missing_ps)} aggregate/system PermissionSet placeholder nodes")

        add_placeholder_profiles_for_users(users, profiles, graph)

    for node in node_builder.build_groups(groups):
        graph.add_or_merge_node(node)

    public_groups = {"records": [g for g in groups.get("records", []) if g.get("Type") == "Regular"]}
    queues_data   = {"records": [g for g in groups.get("records", []) if g.get("Type") == "Queue"]}

    for node in node_builder.build_public_groups(public_groups):
        graph.add_or_merge_node(node)
    for node in node_builder.build_queues(queues_data):
        graph.add_or_merge_node(node)
    for node in node_builder.build_connected_apps(connected_apps):
        graph.add_or_merge_node(node)
    for node in node_builder.build_sobjects(sobjects):
        graph.add_or_merge_node(node)
    for node in node_builder.build_fields(field_permissions):
        graph.add_or_merge_node(node)
    for node in node_builder.build_permission_set_groups(permission_set_groups):
        graph.add_or_merge_node(node)

    # ------------------------------------------------------------------
    # Build SObject lookup (QualifiedApiName → DurableId)
    # ------------------------------------------------------------------
    sobject_lookup = {}
    for obj in sobjects.get("records", []):
        api_name = obj.get("QualifiedApiName")
        node_id  = obj.get("DurableId") or api_name
        if api_name and node_id:
            sobject_lookup[api_name] = node_id

    # ------------------------------------------------------------------
    # Build edges and auto-assign to scope buckets
    # ------------------------------------------------------------------
    edge_builder = EdgeBuilder()
    scope_edge_lists = {scope: [] for scope in VALID_SCOPES}

    def _add_edges(edges_iter):
        """Add edges to the graph and bucket each into its scope list."""
        for edge in edges_iter:
            graph.add_edge_without_validation(edge)
            start_node = graph.get_node_by_id(edge.start_node)
            scope = _edge_scope(edge.kind, start_node)
            if scope:
                scope_edge_lists[scope].append(edge)

    _add_edges(edge_builder.build_profile_assignments(users))
    _add_edges(edge_builder.build_profile_permission_sets(permission_sets))
    _add_edges(edge_builder.build_permission_set_assignments(permission_set_assignments, permission_sets))
    _add_edges(edge_builder.build_role_assignments(users))
    _add_edges(edge_builder.build_role_hierarchy(user_roles))
    _add_edges(edge_builder.build_group_memberships(group_members))
    _add_edges(edge_builder.build_queue_object_access(queue_sobjects, sobject_lookup))
    _add_edges(edge_builder.build_connected_app_creators(connected_apps))
    _add_edges(edge_builder.build_setup_entity_access(setup_entity_access))
    _add_edges(edge_builder.build_object_permissions(object_permissions, sobject_lookup))
    _add_edges(edge_builder.build_field_permissions(field_permissions))
    _add_edges(edge_builder.build_record_ownership_edges(record_owners, sobject_lookup))
    _add_edges(edge_builder.build_profile_system_permissions(profiles, org_node_id))
    _add_edges(edge_builder.build_permission_set_system_permissions(permission_sets, org_node_id))
    _add_edges(edge_builder.build_permission_set_group_assignments(permission_set_group_assignments))
    _add_edges(edge_builder.build_permission_set_group_components(permission_set_group_components))

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    if not active_scopes:
        # Full collection: one monolithic file (original behaviour)
        output_path = os.path.join(base_dir, f"{org_subdomain}_{timestamp}.json")
        graph.print_summary()
        graph.check_dangling()
        graph.export_to_file(output_path, include_metadata=False, indent=2)
        print(f"[+] Graph exported to {output_path}, happy graphing!")

        bh_api = BloodHoundAPI(config)
        if getattr(bh_api, "auto_ingest", False):
            bh_api.upload_graph(output_path)
    else:
        # Scope mode: one file per selected scope
        for scope in sorted(active_scopes):
            _export_scope(scope, graph, scope_edge_lists[scope], base_dir, org_subdomain, timestamp)
        print(f"[+] Scope export complete. Files written to {base_dir}/")


if __name__ == "__main__":
    main()