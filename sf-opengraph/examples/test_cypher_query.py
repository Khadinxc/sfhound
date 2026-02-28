"""
Python script to test Cypher queries against BloodHound API.
Useful for validating queries before running them in the UI.
"""
import sys
import json
import requests
import yaml

CONFIG_PATH = "config.yaml"

session = requests.Session()
with open(CONFIG_PATH, 'r', encoding="utf-8") as f:
    config = yaml.safe_load(f)['bloodhound']
    base_url = config['url']
    username = config['username']
    secret = config['password']


def authenticate():
    """
    Authenticate Function, authenticates to BH API.
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
        "Accept": "application/json",
        "Prefer": "wait=30"
    })

    print("[+] Authenticated successfully")
    return token


def run_cypher(query: str, include_properties: bool = True):
    """
    Execute a Cypher query against BloodHound API.
    
    Args:
        query: Cypher query string
        include_properties: Whether to include node/edge properties in results
    
    Returns:
        dict: API response data
    """
    url = f"{base_url}/api/v2/graphs/cypher"
    payload = {
        "query": query,
        "include_properties": include_properties
    }

    print(f"\n[*] Executing query:\n{query}\n")

    r = session.post(url, json=payload, timeout=60)

    if r.status_code != 200:
        print(f"[!] Query failed (HTTP {r.status_code})")
        print(r.text)
        return None

    try:
        data = r.json()
        print(f"[+] Query successful")
        return data
    except Exception as e:
        print(f"[!] Failed to parse response: {e}")
        print(r.text)
        return None


def print_results(data):
    """Pretty print query results."""
    if not data:
        return

    # Handle different response formats
    if isinstance(data, dict):
        if 'data' in data:
            result_data = data['data']
        else:
            result_data = data
    else:
        result_data = data

    print("\n" + "="*70)
    print("QUERY RESULTS")
    print("="*70)
    print(json.dumps(result_data, indent=2))
    print("="*70 + "\n")


# ---- EXAMPLE QUERIES ----

def test_user_to_object_path():
    """Test: Find ANY path from user to SecretData__c object."""
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet*1..5]->(ps)-[r:CanCreate|CanRead|CanEdit|CanDelete|CanViewAll|CanModifyAll]->(obj:SFSObject)
    WHERE u.name = "KADEN BUTT" AND obj.name = "SECRETDATA__C"
    AND (ps:SFPermissionSet OR ps:SFProfile)
    RETURN path
    LIMIT 10
    """
    return run_cypher(query)


def test_user_crud_permissions():
    """Test: Get all CRUD permissions for a user."""
    query = """
    MATCH (u:SFUser)-[:AssignedProfile|AssignedPermissionSet*1..2]->(p)-[r:CanCreate|CanRead|CanEdit|CanDelete|CanViewAll|CanModifyAll]->(obj:SFSObject)
    WHERE u.name = "KADEN BUTT"
    RETURN u.name as User, 
           p.name as GrantedBy, 
           TYPE(r) as Permission, 
           obj.name as Object, 
           obj.Label as ObjectLabel
    LIMIT 20
    """
    return run_cypher(query)


def test_custom_objects():
    """Test: Find all custom objects."""
    query = """
    MATCH (obj:SFSObject)
    WHERE obj.IsCustom = True
    RETURN obj.name, obj.Label, obj.InternalSharingModel
    """
    return run_cypher(query)


def test_node_exists():
    """Test: Verify specific nodes exist."""
    queries = [
        'MATCH (u:SFUser {name: "KADEN BUTT"}) RETURN u.name, u.Username LIMIT 1',
        'MATCH (obj:SFSObject) WHERE obj.name CONTAINS "Secret" RETURN obj.name, obj.Label LIMIT 5',
        'MATCH (obj:SFSObject {name: "SecretData__c"}) RETURN obj LIMIT 1',
        'MATCH (org:SFOrganization) RETURN org.name, org.subdomain, org.instance_url LIMIT 1'
    ]
    
    results = []
    for query in queries:
        result = run_cypher(query)
        results.append(result)
    
    return results


def test_system_permission_modifyalldata():
    """Test: Find all users with ModifyAllData permission (new Organization model)."""
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet]->(ps)-[:ModifyAllData]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN path
    LIMIT 20
    """
    return run_cypher(query)


def test_system_permission_viewsetup():
    """Test: Find all users with ViewSetup permission."""
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet]->(ps)-[:ViewSetup]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN path
    LIMIT 20
    """
    return run_cypher(query)


def test_system_permission_path_visualization():
    """Test: Visualize path from user to organization through ModifyAllData."""
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet]->(ps)-[:ModifyAllData]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN path
    LIMIT 10
    """
    return run_cypher(query)


def test_user_all_system_permissions():
    """Test: Get all system permissions for a specific user."""
    query = """
    MATCH (u:SFUser {name: "KADEN BUTT"})-[:AssignedProfile|AssignedPermissionSet]->(ps)-[perm]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN u.name AS UserName, 
           ps.name AS PermissionSetOrProfile,
           type(perm) AS SystemPermission
    """
    return run_cypher(query)


def test_all_system_permission_edges():
    """Test: Find all system permission edge types in the graph."""
    query = """
    MATCH (ps)-[perm]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN DISTINCT type(perm) AS PermissionName, COUNT(*) AS Count
    ORDER BY Count DESC
    """
    return run_cypher(query)


def test_field_exists():
    """Test: Verify HighlySensitiveField exists."""
    query = """
    MATCH (f:SFField)
    WHERE f.name = "SECRETDATA__C.HIGHLYSENSITIVEFIELD__C" OR f.name CONTAINS "HighlySensitive"
    RETURN f.name AS FieldName, f.Label AS FieldLabel
    LIMIT 10
    """
    return run_cypher(query)


def test_any_fields_exist():
    """Test: Check if any SFField nodes exist in the graph."""
    query = """
    MATCH (f:SFField)
    RETURN f.name AS FieldName, f.Label AS FieldLabel
    LIMIT 10
    """
    return run_cypher(query)


def test_field_permissions_all():
    """Test: Get all field-level permissions for SecretData fields."""
    query = """
    MATCH (ps:SFPermissionSet)-[perm:IsVisible|ReadOnly]->(f:SFField)
    WHERE f.name CONTAINS "SECRETDATA__C"
    RETURN ps.ProfileId AS ProfileId, 
           ps.name AS PermSetName,
           type(perm) AS PermissionType,
           f.name AS FieldName
    ORDER BY ps.ProfileId, ps.name
    """
    return run_cypher(query)


def test_field_visible_access():
    """Test: Find permission sets with IsVisible access to HighlySensitiveField."""
    query = """
    MATCH (ps:SFPermissionSet)-[:IsVisible]->(f:SFField)
    WHERE f.name = "SECRETDATA__C.HIGHLYSENSITIVEFIELD__C"
    RETURN ps.name AS PermSetName,
           ps.ProfileId AS ProfileId,
           ps.IsOwnedByProfile AS IsOwnedByProfile
    ORDER BY ps.name
    """
    return run_cypher(query)


def test_field_readonly_access():
    """Test: Find permission sets with ReadOnly access to HighlySensitiveField."""
    query = """
    MATCH (ps:SFPermissionSet)-[:ReadOnly]->(f:SFField)
    WHERE f.name = "SECRETDATA__C.HIGHLYSENSITIVEFIELD__C"
    RETURN ps.name AS PermSetName,
           ps.ProfileId AS ProfileId,
           ps.IsOwnedByProfile AS IsOwnedByProfile
    ORDER BY ps.name
    """
    return run_cypher(query)


def test_user_to_field_path():
    """Test: Find paths from users to HighlySensitiveField via Profile.

    Note: Profiles are stored as SFPermissionSet nodes with IsOwnedByProfile = True.
    The SFProfile label is not usable directly in a MATCH pattern in BloodHound's
    Cypher dialect — use SFPermissionSet with IsOwnedByProfile filtering instead.
    """
    query = """
    MATCH (u:SFUser)-[:AssignedProfile]->(prof:SFPermissionSet)-[perm:IsVisible|ReadOnly]->(f:SFField)
    WHERE f.name = "SECRETDATA__C.HIGHLYSENSITIVEFIELD__C"
    AND prof.IsOwnedByProfile = True
    RETURN u.name AS UserName,
           prof.name AS ProfileName,
           type(perm) AS Permission
    LIMIT 10
    """
    return run_cypher(query)


def test_specific_profiles_field_access():
    """Test: Verify specific profiles have correct access to HighlySensitiveField."""
    query = """
    MATCH (ps)-[perm]->(f:SFField)
    WHERE (ps:SFProfile OR ps:SFPermissionSet)
    AND f.name = "SECRETDATA__C.HIGHLYSENSITIVEFIELD__C"
    AND (ps.name IN ["CUSTOM: SUPPORT PROFILE", "INSECURE PROFILE", "SALESFORCE API ONLY SYSTEM INTEGRATIONS", "SYSTEM ADMINISTRATOR"])
    RETURN ps.name AS ProfileOrPermSet,
           type(perm) AS AccessType,
           f.name AS Field
    ORDER BY ps.name
    """
    return run_cypher(query)


def test_all_secretdata_fields():
    """Test: List all fields on SecretData object and their permissions."""
    query = """
    MATCH (f:SFField)
    WHERE f.name CONTAINS "SECRETDATA__C"
    OPTIONAL MATCH (ps:SFPermissionSet)-[perm:IsVisible|ReadOnly]->(f)
    WITH f, COLLECT(DISTINCT type(perm)) AS PermTypes
    RETURN f.name AS FieldName,
           PermTypes AS PermissionTypes
    ORDER BY f.name
    """
    return run_cypher(query)


def test_system_permission_viewalldata():
    """Test: Find all users with ViewAllData permission.

    Modeling accuracy note:
    ViewAllData is a TRUE org-wide bypass — the user can read every record in the
    org regardless of OWD, sharing rules, or role hierarchy. No sharing constraint
    applies. The edge from Profile/PermSet to SFOrganization accurately models this
    as an org-level capability, not an object-level one.
    """
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet]->(ps)-[:ViewAllData]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN path
    LIMIT 20
    """
    return run_cypher(query)


def test_system_permission_apienabled():
    """Test: Find all users with ApiEnabled permission.

    Modeling accuracy note:
    ApiEnabled is a gate permission — it either allows or blocks all programmatic
    API access (REST, SOAP, Bulk, Metadata, Tooling). There is no sharing component;
    if the bit is set the user can call any API endpoint their other permissions
    allow. The edge to SFOrganization is the correct model.
    """
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet]->(ps)-[:ApiEnabled]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN path
    LIMIT 20
    """
    return run_cypher(query)


def test_system_permission_managetranslation():
    """Test: Find all users with ManageTranslation permission.

    Modeling accuracy note:
    ManageTranslation is a Setup-level permission with no record-sharing constraint.
    A holder can override any field label, picklist value, or UI string org-wide.
    The edge to SFOrganization accurately represents the org-wide metadata scope.
    """
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet]->(ps)-[:ManageTranslation]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN path
    LIMIT 20
    """
    return run_cypher(query)


def test_system_permission_edittask():
    """Test: Find all users with EditTask permission.

    Modeling accuracy note:
    EditTask allows editing Task records owned by OTHER users — by default a user
    can only edit tasks they own. However, this permission is SHARING-GATED: the
    user can only edit tasks that are already visible to them via OWD, role hierarchy,
    or sharing rules. It does NOT grant visibility to tasks they cannot already see.

    Risk is compounded when combined with:
      - ViewAllData (can now see + edit every task in the org)
      - A broad OWD on Task (ControlledByParent means access follows the parent record)
      - Role hierarchy (senior roles can see subordinates' tasks)

    The edge to SFOrganization correctly models that this is a SYSTEM PERMISSION
    (not an object-level CRUD edge), because it modifies the ownership-edit restriction
    globally. The sharing caveat is documented in the edge SecurityImpact property.
    """
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet]->(ps)-[:EditTask]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN path
    LIMIT 20
    """
    return run_cypher(query)


def test_system_permission_editevent():
    """Test: Find all users with EditEvent permission.

    Modeling accuracy note:
    EditEvent allows editing Event (calendar activity) records owned by OTHER users.
    Identical sharing constraint as EditTask: the user can only edit events already
    visible to them. Events follow a ControlledByParent OWD model — visibility is
    typically tied to the parent record (Contact, Account, Opportunity, etc.).

    Risk is compounded when combined with:
      - ViewAllData (can see + edit every event in the org)
      - High-level role position (sees subordinates' calendar activity)

    The edge to SFOrganization correctly models the system-permission scope.
    """
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet]->(ps)-[:EditEvent]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN path
    LIMIT 20
    """
    return run_cypher(query)


# ---- RUN ----

def test_sharing_private_objects():
    """Test: Objects with most restrictive sharing (Private)."""
    query = """
    MATCH (obj:SFSObject)
    WHERE obj.InternalSharingModel = "Private"
    RETURN obj
    ORDER BY obj.name
    LIMIT 10
    """
    return run_cypher(query)


def test_sharing_public_objects():
    """Test: Objects with least restrictive sharing (Public Read/Write)."""
    query = """
    MATCH (obj:SFSObject)
    WHERE obj.InternalSharingModel IN ["Public Read/Write", "ReadWrite"]
    RETURN obj
    ORDER BY obj.IsCustom DESC, obj.name
    LIMIT 10
    """
    return run_cypher(query)


def test_sharing_custom_public():
    """Test: Custom objects with public access (potential data leak)."""
    query = """
    MATCH (obj:SFSObject)
    WHERE obj.IsCustom = True
      AND obj.InternalSharingModel IN ["Public Read/Write", "ReadWrite", "Public Read Only", "Read"]
    RETURN obj
    """
    return run_cypher(query)


def test_sharing_mismatch():
    """Test: Sharing model mismatch (internal vs external)."""
    query = """
    MATCH (obj:SFSObject)
    WHERE obj.InternalSharingModel <> obj.ExternalSharingModel
    RETURN obj
    LIMIT 10
    """
    return run_cypher(query)


def test_sharing_distribution():
    """Test: All objects with their sharing models (for analysis)."""
    query = """
    MATCH (obj:SFSObject)
    RETURN obj
    LIMIT 100
    """
    return run_cypher(query)


# ---- QUERIES.MD COVERAGE ----

def test_user_relationship_depth():
    """Test: Relationships to the 6th degree for a specific user (User Hunting)."""
    query = """
    MATCH (u:SFUser)
    WHERE u.name = "PETER WIENER"
    MATCH p = (u)-[*1..6]->(n)
    RETURN DISTINCT p
    """
    return run_cypher(query)


def test_user_to_object_path_shortest():
    """Test: Shortest path to any custom SFSObject (Object Permission Hunting)."""
    query = """
    MATCH p=(u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet|CanCreate|CanRead|CanEdit|CanDelete|CanViewAll|CanModifyAll|IsVisible|ReadOnly|Contains*1..10]->(f:SFSObject)
    WHERE f.name ENDS WITH '__C'
      AND u <> f
    RETURN p
    LIMIT 1000
    """
    return run_cypher(query)


def test_user_to_object_all_shortest_paths():
    """Test: allShortestPaths to any custom SFSObject (Object Permission Hunting)."""
    query = """
    MATCH p=allShortestPaths((u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet|CanCreate|CanRead|CanEdit|CanDelete|CanViewAll|CanModifyAll|IsVisible|ReadOnly|Contains*1..10]->(f:SFSObject))
    WHERE f.name ENDS WITH '__C'
      AND u <> f
    RETURN p
    LIMIT 1000
    """
    return run_cypher(query)


def test_user_to_specific_field_shortest_path():
    """Test: shortestPath from user to a specific SFField (Field Permission Hunting)."""
    query = """
    MATCH p=shortestPath((u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet|CanCreate|CanRead|CanEdit|CanDelete|CanViewAll|CanModifyAll|IsVisible|ReadOnly|Contains*1..10]->(f:SFField))
    WHERE u.name = "PETER WIENER"
      AND f.name = "SECRETDATA__C.HIGHLYSENSITIVEFIELD__C"
      AND u <> f
    RETURN p
    LIMIT 1000
    """
    return run_cypher(query)


def test_crown_jewel_field_shortest_path():
    """Test: Shortest path to crown jewel field for any user (Field Permission Hunting)."""
    query = """
    MATCH p=shortestPath((u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet|CanCreate|CanRead|CanEdit|CanDelete|CanViewAll|CanModifyAll|IsVisible|ReadOnly|Contains*1..10]->(f:SFField))
    WHERE f.name = "SECRETDATA__C.HIGHLYSENSITIVEFIELD__C"
      AND u <> f
    RETURN p
    LIMIT 1000
    """
    return run_cypher(query)


def test_all_users_to_custom_fields():
    """Test: All users with access to any custom fields (Field Permission Hunting)."""
    query = """
    MATCH p=(u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet|CanCreate|CanRead|CanEdit|CanDelete|CanViewAll|CanModifyAll|IsVisible|ReadOnly|Contains*1..10]->(f:SFField)
    WHERE f.name ENDS WITH '__C'
      AND u <> f
    RETURN p
    LIMIT 1000
    """
    return run_cypher(query)


def test_count_all_users():
    """Test: Generic count — all SFUser nodes."""
    query = """
    MATCH (m:SFUser) RETURN m
    """
    return run_cypher(query)


def test_count_all_permission_sets():
    """Test: Generic count — all SFPermissionSet nodes."""
    query = """
    MATCH (m:SFPermissionSet) RETURN m
    """
    return run_cypher(query)


def test_all_nodes_and_relationships():
    """Test: All nodes and relationships (expensive — limited to 500)."""
    query = """
    MATCH (n)
    OPTIONAL MATCH (n)-[r]->(m)
    RETURN n, r, m
    LIMIT 500
    """
    return run_cypher(query)


def test_system_permission_high_risk_path():
    """Test: Shortest path to org compromise via Tier-0 permissions (System Permission Queries)."""
    query = """
    MATCH p=(u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet*1..5]->(ps)-[r:ModifyAllData|ManageSharing|ManageProfilesPermissionsets|CustomizeApplication|AuthorApex|ManageUsers|ManageRoles]->(org:SFOrganization)
    WHERE (ps:SFProfile OR ps:SFPermissionSet)
      AND u <> org
    RETURN p
    LIMIT 1000
    """
    return run_cypher(query)


def test_user_system_permissions_by_username():
    """Test: All system permissions for a user looked up by Username (System Permission Queries)."""
    query = """
    MATCH (u:SFUser {Username: "username@example.com"})-[:AssignedProfile|AssignedPermissionSet]->(ps)-[perm]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN u.name AS UserName,
           ps.name AS PermissionSetOrProfile,
           type(perm) AS SystemPermission
    """
    return run_cypher(query)


def test_count_users_per_system_permission():
    """Test: How many users hold each system permission (System Permission Queries)."""
    query = """
    MATCH (u:SFUser)-[:AssignedProfile|AssignedPermissionSet]->(ps)-[perm]->(org:SFOrganization)
    WHERE ps:SFProfile OR ps:SFPermissionSet
    RETURN type(perm) AS Permission, COUNT(DISTINCT u) AS UserCount
    ORDER BY UserCount DESC
    """
    return run_cypher(query)


def test_role_hierarchy_user_assignments():
    """Test: All users and their role assignments (Role Hierarchy Queries)."""
    query = """
    MATCH (u:SFUser)-[h:HasRole]->(r:SFRole)
    RETURN u, h, r
    """
    return run_cypher(query)


def test_role_hierarchy_tree():
    """Test: Role hierarchy tree up to 5 levels (Role Hierarchy Queries)."""
    query = """
    MATCH path = (child:SFRole)-[:InheritsRole*1..5]->(ancestor:SFRole)
    WHERE NOT (ancestor)-[:InheritsRole]->()
    RETURN path
    """
    return run_cypher(query)


def test_portal_role_users():
    """Test: Users assigned to portal roles (Role Hierarchy Queries)."""
    query = """
    MATCH (u:SFUser)-[:HasRole]->(r:SFRole)
    WHERE r.IsPortalRole = True
    RETURN u, r
    """
    return run_cypher(query)


def test_all_public_groups():
    """Test: All SFGroup (Public Group) nodes (Group & Queue Queries)."""
    query = """
    MATCH (g:SFGroup)
    RETURN g
    """
    return run_cypher(query)


def test_group_membership():
    """Test: Public Group membership including nested groups (Group & Queue Queries)."""
    query = """
    MATCH (g:SFGroup)-[h:HasMember]->(m)
    RETURN g, h, m
    """
    return run_cypher(query)


def test_specific_group_members():
    """Test: Users in a specific Public Group via nested membership (Group & Queue Queries)."""
    query = """
    MATCH path = (g:SFGroup {name: 'KaiberSecInternalUsers'})-[:HasMember*1..3]->(u:SFUser)
    RETURN path
    """
    return run_cypher(query)


def test_all_queues():
    """Test: All SFQueue nodes (Group & Queue Queries)."""
    query = """
    MATCH (q:SFQueue)
    RETURN q
    """
    return run_cypher(query)


def test_queue_members():
    """Test: Queue membership (Group & Queue Queries)."""
    query = """
    MATCH (q:SFQueue)-[h:HasMember]->(m)
    RETURN q, h, m
    """
    return run_cypher(query)


def test_all_connected_apps():
    """Test: All SFConnectedApp nodes (Connected App Queries)."""
    query = """
    MATCH (app:SFConnectedApp)
    RETURN app
    """
    return run_cypher(query)


def test_connected_apps_creators():
    """Test: ConnectedApps and their creating users (Connected App Queries)."""
    query = """
    MATCH p = (app:SFConnectedApp)-[:CreatedBy]->(u:SFUser)
    RETURN p
    """
    return run_cypher(query)


def test_admin_most_apps():
    """Test: Which admin created the most ConnectedApps (Connected App Queries)."""
    query = """
    MATCH (app:SFConnectedApp)-[:CreatedBy]->(u:SFUser)
    RETURN u.name AS Admin, count(app) AS AppCount
    ORDER BY AppCount DESC
    """
    return run_cypher(query)


def test_profiles_can_authorize_apps():
    """Test: Which Profiles/PermissionSets can authorize ConnectedApps (Connected App Queries)."""
    query = """
    MATCH p = (ps)-[:CanAuthorize]->(app:SFConnectedApp)
    RETURN p
    """
    return run_cypher(query)


def test_user_to_connected_app_path():
    """Test: Attack path from user to ConnectedApp authorization (Connected App Queries)."""
    query = """
    MATCH path = (u:SFUser)-[:AssignedProfile|AssignedPermissionSet*1..2]->(ps)-[:CanAuthorize]->(app:SFConnectedApp)
    RETURN path
    """
    return run_cypher(query)


def test_self_authorization_apps():
    """Test: ConnectedApps that allow self-authorization (Connected App Queries)."""
    query = """
    MATCH (app:SFConnectedApp)
    WHERE app.AdminApprovedUsersOnly = False
    RETURN app.name, app.AdminApprovedUsersOnly, app.CreatedDate
    """
    return run_cypher(query)


def test_users_can_delete_object():
    """Test: All users who can delete a specific object (SObject & CRUD Permission Queries)."""
    query = """
    MATCH (u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet*1..5]->(p)-[:CanDelete]->(obj:SFSObject {name: "SECRETDATA__C"})
    WHERE (p:SFPermissionSet OR p:SFProfile)
    RETURN DISTINCT u.name as User, p.name as GrantedBy, obj.Label as Object
    """
    return run_cypher(query)


def test_users_with_modify_all_custom():
    """Test: Users with CanModifyAll on any custom object — sharing-rule bypass (SObject & CRUD)."""
    query = """
    MATCH (u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet*1..5]->(p)-[:CanModifyAll]->(obj:SFSObject)
    WHERE obj.IsCustom = True
    AND (p:SFPermissionSet OR p:SFProfile)
    RETURN DISTINCT u.name as User, obj.name as CustomObject, obj.Label
    ORDER BY u.name, obj.name
    """
    return run_cypher(query)


def test_users_suspicious_permissions():
    """Test: Users with Create + Delete + ModifyAll on the same object (SObject & CRUD).

    Note: Triple variable-length traversal is expensive. Depth is capped at 1..3
    to stay within BloodHound's query-complexity limit. Increase to 1..5 if you
    need to chase PermissionSetGroup chains, but expect slower execution.
    """
    query = """
    MATCH (u:SFUser)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet*1..3]->(p1)-[:CanCreate]->(obj:SFSObject),
          (u)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet*1..3]->(p2)-[:CanDelete]->(obj),
          (u)-[:AssignedProfile|AssignedPermissionSet|AssignedPermissionSetGroup|HasPermissionSet|IncludesPermissionSet*1..3]->(p3)-[:CanModifyAll]->(obj)
    WHERE (p1:SFPermissionSet OR p1:SFProfile)
    AND (p2:SFPermissionSet OR p2:SFProfile)
    AND (p3:SFPermissionSet OR p3:SFProfile)
    RETURN DISTINCT u.name, obj.name, obj.Label
    """
    return run_cypher(query)


if __name__ == "__main__":
    authenticate()

    print("\n" + "="*70)
    print("TESTING CYPHER QUERIES")
    print("="*70)

    # Test 1: Verify nodes exist (includes Organization node)
    print("\n[TEST 1] Verifying nodes exist...")
    test_node_exists()

    # Test 2: Custom objects
    print("\n[TEST 2] Finding custom objects...")
    result = test_custom_objects()
    print_results(result)

    # Test 3: User CRUD permissions
    print("\n[TEST 3] User CRUD permissions...")
    result = test_user_crud_permissions()
    print_results(result)

    # Test 4: Path from user to object
    print("\n[TEST 4] Path from user to SecretData__c...")
    result = test_user_to_object_path()
    print_results(result)

    # Test 5: System permission - ModifyAllData (NEW)
    print("\n[TEST 5] Users with ModifyAllData permission...")
    result = test_system_permission_modifyalldata()
    print_results(result)

    # Test 6: System permission - ViewSetup (NEW)
    print("\n[TEST 6] Users with ViewSetup permission...")
    result = test_system_permission_viewsetup()
    print_results(result)

    # Test 7: All system permissions for a user (NEW)
    print("\n[TEST 7] All system permissions for KADEN BUTT...")
    result = test_user_all_system_permissions()
    print_results(result)

    # Test 8: All system permission edge types (NEW)
    print("\n[TEST 8] All system permission types in graph...")
    result = test_all_system_permission_edges()
    print_results(result)

    # Test 9: Path visualization (NEW)
    print("\n[TEST 9] Path visualization: User -> Profile/PermSet -> Org...")
    result = test_system_permission_path_visualization()
    print_results(result)

    # Test 10: Check if any fields exist
    print("\n[TEST 10] Checking if any SFField nodes exist...")
    result = test_any_fields_exist()
    print_results(result)

    # Test 11: Field existence
    print("\n[TEST 11] Verifying HighlySensitiveField exists...")
    result = test_field_exists()
    print_results(result)

    # Test 12: All field permissions for HighlySensitiveField
    print("\n[TEST 12] All field-level permissions...")
    result = test_field_permissions_all()
    print_results(result)

    # Test 13: Profiles with IsVisible access
    print("\n[TEST 13] Profiles with IsVisible (editable) access to HighlySensitiveField...")
    result = test_field_visible_access()
    print_results(result)

    # Test 14: Profiles with ReadOnly access
    print("\n[TEST 14] Profiles with ReadOnly access to HighlySensitiveField...")
    result = test_field_readonly_access()
    print_results(result)

    # Test 15: Specific profiles verification
    print("\n[TEST 15] Verifying specific profile access...")
    result = test_specific_profiles_field_access()
    print_results(result)

    # Test 16: User to field paths
    print("\n[TEST 16] Paths from users to HighlySensitiveField...")
    result = test_user_to_field_path()
    print_results(result)

    # Test 17: All SecretData fields
    print("\n[TEST 17] All fields on SecretData__c object...")
    result = test_all_secretdata_fields()
    print_results(result)

    # Test 18: Sharing Model Tests
    print("\n[TEST 18] Objects with Private sharing model...")
    result = test_sharing_private_objects()
    print_results(result)

    print("\n[TEST 19] Objects with Public Read/Write sharing...")
    result = test_sharing_public_objects()
    print_results(result)

    print("\n[TEST 20] Custom objects with public access...")
    result = test_sharing_custom_public()
    print_results(result)

    print("\n[TEST 21] Sharing model mismatch (internal vs external)...")
    result = test_sharing_mismatch()
    print_results(result)

    print("\n[TEST 22] All objects with sharing models (for analysis)...")
    result = test_sharing_distribution()
    print_results(result)

    # Test 23: ViewAllData permission
    print("\n[TEST 23] Users with ViewAllData permission...")
    print("[NOTE] Modeling: true org-wide read bypass — no sharing constraint.")
    result = test_system_permission_viewalldata()
    print_results(result)

    # Test 24: ApiEnabled permission
    print("\n[TEST 24] Users with ApiEnabled permission...")
    print("[NOTE] Modeling: gate permission — allows ALL API access, no sharing component.")
    result = test_system_permission_apienabled()
    print_results(result)

    # Test 25: ManageTranslation permission
    print("\n[TEST 25] Users with ManageTranslation permission...")
    print("[NOTE] Modeling: Setup-level permission, org-wide metadata scope. No sharing constraint.")
    result = test_system_permission_managetranslation()
    print_results(result)

    # Test 26: EditTask permission
    print("\n[TEST 26] Users with EditTask permission...")
    print("[NOTE] Modeling accuracy: SHARING-GATED. User can edit other users' tasks ONLY if"
          " those tasks are already visible via OWD/role hierarchy/sharing rules.")
    print("[NOTE] Blast radius expands significantly when combined with ViewAllData.")
    result = test_system_permission_edittask()
    print_results(result)

    # Test 27: EditEvent permission
    print("\n[TEST 27] Users with EditEvent permission...")
    print("[NOTE] Modeling accuracy: SHARING-GATED. User can edit other users' events ONLY if"
          " those events are already visible. Events follow ControlledByParent OWD.")
    print("[NOTE] Blast radius expands significantly when combined with ViewAllData.")
    result = test_system_permission_editevent()
    print_results(result)

    # ---- QUERIES.MD COVERAGE ----

    # Test 28: User Hunting — relationships to 6th degree
    print("\n[TEST 28] User Hunting — relationships to 6th degree for PETER WIENER...")
    result = test_user_relationship_depth()
    print_results(result)

    # Test 29: Shortest path to any custom SFSObject
    print("\n[TEST 29] Shortest path (any user) to any custom SFSObject...")
    result = test_user_to_object_path_shortest()
    print_results(result)

    # Test 30: allShortestPaths to any custom SFSObject
    print("\n[TEST 30] allShortestPaths (any user) to any custom SFSObject...")
    result = test_user_to_object_all_shortest_paths()
    print_results(result)

    # Test 31: shortestPath from user to specific field
    print("\n[TEST 31] shortestPath from PETER WIENER to HighlySensitiveField...")
    result = test_user_to_specific_field_shortest_path()
    print_results(result)

    # Test 32: Shortest path (all users) to crown jewel field
    print("\n[TEST 32] shortestPath (all users) to HighlySensitiveField...")
    result = test_crown_jewel_field_shortest_path()
    print_results(result)

    # Test 33: All users with access to any custom fields
    print("\n[TEST 33] All users with access to any custom fields...")
    result = test_all_users_to_custom_fields()
    print_results(result)

    # Test 34: Generic count — all SFUser nodes
    print("\n[TEST 34] Generic count — all SFUser nodes...")
    result = test_count_all_users()
    print_results(result)

    # Test 35: Generic count — all SFPermissionSet nodes
    print("\n[TEST 35] Generic count — all SFPermissionSet nodes...")
    result = test_count_all_permission_sets()
    print_results(result)

    # Test 36: All nodes and relationships (limited sample)
    print("\n[TEST 36] All nodes and relationships (LIMIT 500)...")
    result = test_all_nodes_and_relationships()
    print_results(result)

    # Test 37: High-risk system permission path (Tier-0 org compromise)
    print("\n[TEST 37] Shortest path to org compromise via Tier-0 permissions...")
    result = test_system_permission_high_risk_path()
    print_results(result)

    # Test 38: System permissions by Username lookup
    print("\n[TEST 38] System permissions for username@example.com (by Username field)...")
    result = test_user_system_permissions_by_username()
    print_results(result)

    # Test 39: Count users per system permission
    print("\n[TEST 39] User count per system permission...")
    result = test_count_users_per_system_permission()
    print_results(result)

    # Test 40: Role — all user assignments
    print("\n[TEST 40] All users and their role assignments...")
    result = test_role_hierarchy_user_assignments()
    print_results(result)

    # Test 41: Role hierarchy tree (up to 5 levels)
    print("\n[TEST 41] Role hierarchy tree (up to 5 levels)...")
    result = test_role_hierarchy_tree()
    print_results(result)

    # Test 42: Portal role users
    print("\n[TEST 42] Users assigned to portal roles...")
    result = test_portal_role_users()
    print_results(result)

    # Test 43: All Public Groups
    print("\n[TEST 43] All Public Groups (SFGroup nodes)...")
    result = test_all_public_groups()
    print_results(result)

    # Test 44: Public Group membership
    print("\n[TEST 44] Public Group membership (including nested)...")
    result = test_group_membership()
    print_results(result)

    # Test 45: Users in specific Public Group
    print("\n[TEST 45] Users in KaiberSecInternalUsers group (nested up to 3 levels)...")
    result = test_specific_group_members()
    print_results(result)

    # Test 46: All Queues
    print("\n[TEST 46] All SFQueue nodes...")
    result = test_all_queues()
    print_results(result)

    # Test 47: Queue members
    print("\n[TEST 47] Queue membership...")
    result = test_queue_members()
    print_results(result)

    # Test 48: All ConnectedApps
    print("\n[TEST 48] All SFConnectedApp nodes...")
    result = test_all_connected_apps()
    print_results(result)

    # Test 49: ConnectedApps and creators
    print("\n[TEST 49] ConnectedApps and their creating users...")
    result = test_connected_apps_creators()
    print_results(result)

    # Test 50: Admin who created the most apps
    print("\n[TEST 50] Admin who created the most ConnectedApps...")
    result = test_admin_most_apps()
    print_results(result)

    # Test 51: Profiles/PermSets that can authorize ConnectedApps
    print("\n[TEST 51] Profiles/PermSets with CanAuthorize on ConnectedApps...")
    result = test_profiles_can_authorize_apps()
    print_results(result)

    # Test 52: User to ConnectedApp attack path
    print("\n[TEST 52] Attack path: User -> PermSet/Profile -> ConnectedApp...")
    result = test_user_to_connected_app_path()
    print_results(result)

    # Test 53: ConnectedApps allowing self-authorization
    print("\n[TEST 53] ConnectedApps with AdminApprovedUsersOnly = False...")
    result = test_self_authorization_apps()
    print_results(result)

    # Test 54: Users who can delete a specific object
    print("\n[TEST 54] Users who can delete SECRETDATA__C...")
    result = test_users_can_delete_object()
    print_results(result)

    # Test 55: Users with CanModifyAll on any custom object
    print("\n[TEST 55] Users with CanModifyAll on any custom object (sharing bypass)...")
    result = test_users_with_modify_all_custom()
    print_results(result)

    # Test 56: Users with suspicious permissions (Create + Delete + ModifyAll)
    print("\n[TEST 56] Users with Create + Delete + ModifyAll on the same object...")
    result = test_users_suspicious_permissions()
    print_results(result)

    print("\n[+] All tests complete!")
