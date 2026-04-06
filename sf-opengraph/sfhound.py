"""
sfhound.py, the bones of the operation. Sniffing sales so you don't have to.
All the work happens in this module wiring all the supporting functions together.
"""
import sys
import os
from datetime import datetime
from urllib.parse import urlparse
import yaml
import argparse


from extractor.auth import SalesforceAuth
from extractor.metadata import MetadataExtractor
from extractor.assignments import AssignmentExtractor

from graph.nodes import NodeBuilder, make_node
from graph.edges import EdgeBuilder
from graph.sfgraph import SFGraph
from bloodhound_api import BloodHoundAPI

CONFIG_PATH = "config.yaml"


def parse_arguments():
    """Parse command-line arguments to override config.yaml values."""
    parser = argparse.ArgumentParser(
        description="SFHound - Six Degrees of System Administrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use config.yaml (default)
  python sfhound.py

  # Override Salesforce credentials
  python sfhound.py --client-id YOUR_ID --username user@example.com

  # Override output directory
  python sfhound.py --output-path /custom/output/dir

  # Complete override
  python sfhound.py --client-id ID --client-secret SECRET --username user@example.com \\
                 --private-key /path/to/key.pem --login-url https://test.salesforce.com
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
    sf_group.add_argument("--client-id", help="Salesforce Connected App Client ID")
    sf_group.add_argument("--client-secret", help="Salesforce Connected App Client Secret")
    sf_group.add_argument("--username", help="Salesforce username")
    sf_group.add_argument("--private-key", help="Path to private key file for JWT authentication")
    sf_group.add_argument("--login-url", help="Salesforce login URL (default: https://login.salesforce.com)")
    sf_group.add_argument("--api-version", help="Salesforce API version (default: v56.0)")
    
    # Output settings
    output_group = parser.add_argument_group("Output settings")
    output_group.add_argument("--output-path", help="Directory for output JSON files (default: ./opengraph_output)")

    # BloodHound CE integration
    bh_group = parser.add_argument_group("BloodHound CE integration")
    bh_group.add_argument("--auto-ingest", action="store_true", default=None,
                          help="Clear the BloodHound database and upload the graph after export")
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

    # Validate required fields
    sf_config = config.get('salesforce', {})
    required = ['client_id', 'username', 'private_key', 'login_url']
    missing = [field for field in required if not sf_config.get(field)]
    
    if missing:
        print(f"[!] Error: Missing required Salesforce configuration fields: {', '.join(missing)}")
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
        soql = f"""
        SELECT Id, Name, UserLicenseId, Description, CreatedDate, LastModifiedDate, SystemModstamp
        FROM Profile
        WHERE Id IN ({quoted})
        """
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


def build_output_path(config: dict) -> str:
    """Build output file path from config."""
    login_url = config["salesforce"]["login_url"]
    base_output_dir = config.get("env", {}).get("output_path", "./opengraph_output")

    # Ensure directory exists
    os.makedirs(base_output_dir, exist_ok=True)

    # Extract org subdomain safely
    parsed = urlparse(login_url)
    hostname = parsed.hostname or "unknown"
    org_subdomain = hostname.split(".")[0]

    # Safe timestamp
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    filename = f"{org_subdomain}_{timestamp}.json"
    return os.path.join(base_output_dir, filename)


def main():
    """Main graph export function."""
    args = parse_arguments()
    config = load_config(args)
    
    output_path = build_output_path(config)

    auth = SalesforceAuth(config)
    auth.authenticate()

    # -----------------------------
    # Phase 1 — Metadata extraction
    # -----------------------------
    metadata_extractor = MetadataExtractor(auth)

    profiles = metadata_extractor.extract_profiles()
    permission_sets = metadata_extractor.extract_permission_sets()
    groups = metadata_extractor.extract_groups()
    permission_set_groups = metadata_extractor.extract_permission_set_groups()
    permission_set_group_components = metadata_extractor.extract_permission_set_group_components()
    user_roles = metadata_extractor.extract_user_roles()
    queue_sobjects = metadata_extractor.extract_queue_sobjects()
    connected_apps = metadata_extractor.extract_connected_apps()
    setup_entity_access = metadata_extractor.extract_setup_entity_access()
    sobjects = metadata_extractor.extract_sobjects()
    object_permissions = metadata_extractor.extract_object_permissions()
    field_permissions = metadata_extractor.extract_field_permissions()

    # -----------------------------
    # Phase 2 — Assignment extraction
    # -----------------------------
    assignment_extractor = AssignmentExtractor(auth)
    users = assignment_extractor.extract_users()
    permission_set_assignments = assignment_extractor.extract_permission_set_assignments()
    group_members = assignment_extractor.extract_group_members()
    permission_set_group_assignments = assignment_extractor.extract_permission_set_group_assignments()
    record_owners = assignment_extractor.extract_record_owners(sobjects)

    # -----------------------------
    # Hydrate missing Profiles (best effort)
    # -----------------------------
    profiles = hydrate_missing_profiles(metadata_extractor, users, profiles)

    # -----------------------------
    # Phase 3 — Permissions extraction (enable when ready)
    # -----------------------------
    # obj_perms = assignment_extractor.extract_object_permissions()
    # field_perms = assignment_extractor.extract_field_permissions()

    # -----------------------------
    # Normalize nodes
    # -----------------------------
    node_builder = NodeBuilder()
    graph = SFGraph()

    # Organization node (represents the Salesforce org itself)
    # System-level permissions will be edges to this node
    org_node = node_builder.build_organization(auth.instance_url)
    org_node_id = org_node.id
    graph.add_or_merge_node(org_node)

    # Core identity/meta nodes
    for node in node_builder.build_users(users):
        graph.add_or_merge_node(node)
    for node in node_builder.build_profiles(profiles):
        graph.add_or_merge_node(node)
    for node in node_builder.build_permission_sets(permission_sets):
        graph.add_or_merge_node(node)
    for node in node_builder.build_roles(user_roles):
        graph.add_or_merge_node(node)

    # Hydrate aggregate/system PermissionSet nodes that are not returned by
    # SELECT FROM PermissionSet. Salesforce generates internal PermSets for
    # PermissionSetGroups whose IDs appear in ObjectPermissions.ParentId but
    # are not queryable as standalone PermissionSet records.
    _ps_node_ids = {
        nid for nid, n in graph.nodes.items()
        if any(k in ("SFPermissionSet", "SFProfile") for k in n.kinds)
    }
    _ps_parent_map = {}  # normalized -> original
    for _perm in (*object_permissions.get("records", []), *field_permissions.get("records", [])):
        _pid = _perm.get("ParentId")
        if _pid:
            _ps_parent_map[_pid.strip().upper()] = _pid
    _missing_ps = {orig for norm, orig in _ps_parent_map.items() if norm not in _ps_node_ids}
    if _missing_ps:
        _placeholder_ps = {"records": [{"Id": pid, "Name": f"[AggregatePermSet] {pid}"} for pid in _missing_ps]}
        for node in node_builder.build_permission_sets(_placeholder_ps):
            graph.add_or_merge_node(node)
        print(f"[+] Hydrated {len(_missing_ps)} aggregate/system PermissionSet placeholder nodes")

    # Safety net: if hydration still missed any profile ids, add placeholders now
    add_placeholder_profiles_for_users(users, profiles, graph)

    # Groups: always build generic Group nodes so GroupMember edges never dangle
    for node in node_builder.build_groups(groups):
        graph.add_or_merge_node(node)

    public_groups = {"records": [g for g in groups.get("records", []) if g.get("Type") == "Regular"]}
    queues = {"records": [g for g in groups.get("records", []) if g.get("Type") == "Queue"]}

    for node in node_builder.build_public_groups(public_groups):
        graph.add_or_merge_node(node)
    for node in node_builder.build_queues(queues):
        graph.add_or_merge_node(node)
    for node in node_builder.build_connected_apps(connected_apps):
        graph.add_or_merge_node(node)
    for node in node_builder.build_sobjects(sobjects):
        graph.add_or_merge_node(node)
    for node in node_builder.build_fields(field_permissions):
        graph.add_or_merge_node(node)

    # NOTE: System permissions are now modeled as edges to the Organization node,
    # not as separate nodes. See edge building section below.

    # Permission Set Groups
    for node in node_builder.build_permission_set_groups(permission_set_groups):
        graph.add_or_merge_node(node)

    # -----------------------------
    # Build edges into graph
    # -----------------------------
    edge_builder = EdgeBuilder()

    # User -> Profile
    for edge in edge_builder.build_profile_assignments(users):
        graph.add_edge_without_validation(edge)

    # Profile -> PermissionSet (for profile-owned permsets)
    for edge in edge_builder.build_profile_permission_sets(permission_sets):
        graph.add_edge_without_validation(edge)

    # User -> PermissionSet (DIRECT assignments only)
    for edge in edge_builder.build_permission_set_assignments(permission_set_assignments, permission_sets):
        graph.add_edge_without_validation(edge)

    # User -> Role / Role hierarchy
    for edge in edge_builder.build_role_assignments(users):
        graph.add_edge_without_validation(edge)
    for edge in edge_builder.build_role_hierarchy(user_roles):
        graph.add_edge_without_validation(edge)

    # User/Group -> Group
    for edge in edge_builder.build_group_memberships(group_members):
        graph.add_edge_without_validation(edge)

    # Build SobjectType API name -> SFSObject node ID lookup (shared by queue and CRUD edge builders)
    sobject_lookup = {}
    for obj in sobjects.get("records", []):
        api_name = obj.get("QualifiedApiName")
        # Use DurableId as node ID (matches what build_sobjects uses)
        node_id = obj.get("DurableId") or api_name
        if api_name and node_id:
            sobject_lookup[api_name] = node_id

    # Queue -> Object access (which object types each Queue can own)
    for edge in edge_builder.build_queue_object_access(queue_sobjects, sobject_lookup):
        graph.add_edge_without_validation(edge)

    # ConnectedApp -> User (creation tracking)
    for edge in edge_builder.build_connected_app_creators(connected_apps):
        graph.add_edge_without_validation(edge)

    # Profile/PermissionSet -> ConnectedApp (authorization grants)
    for edge in edge_builder.build_setup_entity_access(setup_entity_access):
        graph.add_edge_without_validation(edge)

    # Profile/PermissionSet -> SObject (CRUD permissions)
    for edge in edge_builder.build_object_permissions(object_permissions, sobject_lookup):
        graph.add_edge_without_validation(edge)
    for edge in edge_builder.build_field_permissions(field_permissions):
        graph.add_edge_without_validation(edge)

    # User -> SObject (record ownership, enables role-hierarchy access path analysis)
    for edge in edge_builder.build_record_ownership_edges(record_owners, sobject_lookup):
        graph.add_edge_without_validation(edge)

    # System permission edges (Profile/PermissionSet -> Organization)
    # Each system permission (e.g., ModifyAllData, ViewSetup) becomes an edge to the Organization
    for edge in edge_builder.build_profile_system_permissions(profiles, org_node_id):
        graph.add_edge_without_validation(edge)
    for edge in edge_builder.build_permission_set_system_permissions(permission_sets, org_node_id):
        graph.add_edge_without_validation(edge)

    # PermissionSetGroup relationships
    for edge in edge_builder.build_permission_set_group_assignments(permission_set_group_assignments):
        graph.add_edge_without_validation(edge)
    for edge in edge_builder.build_permission_set_group_components(permission_set_group_components):
        graph.add_edge_without_validation(edge)

    # -----------------------------
    # Summary, dangling-edge check, and export
    # -----------------------------
    graph.print_summary()
    graph.check_dangling()
    graph.export_to_file(output_path, include_metadata=False, indent=2)
    print(f"[+] Graph exported to {output_path}, happy graphing!")

    # -----------------------------
    # BloodHound API integration
    # -----------------------------
    bh_api = BloodHoundAPI(config)
    if getattr(bh_api, "auto_ingest", False):
        bh_api.upload_graph(output_path)


if __name__ == "__main__":
    main()