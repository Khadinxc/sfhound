from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from bhopengraph.Node import Node as _BHNode
from bhopengraph.Properties import Properties as _BHProperties

_PRIMITIVE_TYPES = (str, int, float, bool)


def _filter_nulls(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


def _norm_sf_id(v: str | None) -> str | None:
    if not v:
        return v
    return v.strip().upper()


def make_node(
    node_id: str,
    kinds: Iterable[str] | str,
    properties: Optional[Dict[str, Any]] = None,
) -> _BHNode:
    """
    Create a bhopengraph.Node from sfhound collector data.

    - Normalises node_id (strip + uppercase, consistent with Salesforce ID casing)
    - Converts a bare string kind to a single-element list
    - Drops None and non-primitive property values (bhopengraph.Properties only
      accepts str / int / float / bool and homogeneous primitive lists)
    - Sets 'objectid' to the normalised node_id if not already present
    """
    node_id = _norm_sf_id(node_id) or node_id
    kinds_list = [kinds] if isinstance(kinds, str) else list(kinds)
    props_dict: Dict[str, Any] = dict(properties or {})
    props_dict.setdefault("objectid", node_id)
    clean = {
        k: v for k, v in props_dict.items()
        if v is not None and isinstance(v, _PRIMITIVE_TYPES)
    }
    return _BHNode(node_id, kinds_list, _BHProperties(**clean))


class NodeBuilder:
    """
    Builds graph nodes from Salesforce API payloads.

    This layer should ONLY normalize data into nodes.
    Privilege resolution and inheritance belongs in edge builders.
    """

    # ============================================================
    # Identity Nodes
    # ============================================================

    def build_users(self, users: Dict[str, Any]) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []

        for u in users.get("records", []):
            display_name = (
                u.get("Name")
                or u.get("Username")
                or u.get("Email")
                or u.get("Id")
            )

            props = _filter_nulls(
                {
                    "name": display_name,
                    "Username": u.get("Username"),
                    "Email": u.get("Email"),
                    "Alias": u.get("Alias"),
                    "FederationIdentifier": u.get("FederationIdentifier"),
                    "IsActive": u.get("IsActive"),
                    "UserType": u.get("UserType"),
                    "LastLoginDate": u.get("LastLoginDate"),
                    "LastPasswordChangeDate": u.get("LastPasswordChangeDate"),
                    "TimeZoneSidKey": u.get("TimeZoneSidKey"),
                    "LocaleSidKey": u.get("LocaleSidKey"),
                    "LanguageLocaleKey": u.get("LanguageLocaleKey"),
                    "EmailEncodingKey": u.get("EmailEncodingKey"),
                    "ProfileId": u.get("ProfileId"),
                    "ProfileName": (u.get("Profile", {}) or {}).get("Name"),
                    "UserRoleId": u.get("UserRoleId"),
                    "UserRoleName": (u.get("UserRole", {}) or {}).get("Name"),
                    "ManagerId": u.get("ManagerId"),
                    "ManagerName": (u.get("Manager", {}) or {}).get("Name"),
                    "CreatedDate": u.get("CreatedDate"),
                    "LastModifiedDate": u.get("LastModifiedDate"),
                }
            )

            nodes.append(make_node(u["Id"], "SFUser", props))

        return nodes

    def build_profiles(self, profiles: Dict[str, Any]) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []

        for p in profiles.get("records", []):
            props = _filter_nulls(
                {
                    "name": p.get("Name") or p.get("Id"),
                    "UserLicenseId": p.get("UserLicenseId"),
                    "UserType": p.get("UserType"),
                    "Description": p.get("Description"),
                    "CreatedDate": p.get("CreatedDate"),
                    "LastModifiedDate": p.get("LastModifiedDate"),
                    "SystemModstamp": p.get("SystemModstamp") or p.get("SystemModStamp"),
                }
            )

            nodes.append(make_node(p["Id"], "SFProfile", props))

        return nodes

    def build_permission_sets(self, permsets: Dict[str, Any]) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []

        for ps in permsets.get("records", []):
            label = ps.get("Label")
            api_name = ps.get("Name")
            display_name = label or api_name or ps.get("Id")

            props = _filter_nulls(
                {
                    "name": display_name,
                    "Label": label,
                    "ApiName": api_name,
                    "IsOwnedByProfile": ps.get("IsOwnedByProfile"),
                    "ProfileId": ps.get("ProfileId"),
                    "LicenseId": ps.get("LicenseId"),
                    "Type": ps.get("Type"),
                    "HasActivationRequired": ps.get("HasActivationRequired"),
                    "IsCustom": ps.get("IsCustom"),
                    "CreatedDate": ps.get("CreatedDate"),
                    "LastModifiedDate": ps.get("LastModifiedDate"),
                    "SystemModstamp": ps.get("SystemModstamp") or ps.get("SystemModStamp"),
                }
            )

            nodes.append(make_node(ps["Id"], "SFPermissionSet", props))

        return nodes

    def build_roles(self, roles: Dict[str, Any]) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []

        for r in roles.get("records", []):
            # Determine if this is a portal role
            portal_type = r.get("PortalType")
            is_portal = portal_type not in (None, "None")
            
            props = _filter_nulls(
                {
                    "name": r.get("Name"),
                    "DeveloperName": r.get("DeveloperName"),
                    "ParentRoleId": r.get("ParentRoleId"),
                    "Description": r.get("RollupDescription"),
                    "OpportunityAccessForAccountOwner": r.get("OpportunityAccessForAccountOwner"),
                    "CaseAccessForAccountOwner": r.get("CaseAccessForAccountOwner"),
                    "ContactAccessForAccountOwner": r.get("ContactAccessForAccountOwner"),
                    "PortalType": portal_type,
                    "PortalRole": r.get("PortalRole"),
                    "PortalAccountId": r.get("PortalAccountId"),
                    "IsPortalRole": is_portal,
                    "LastModifiedDate": r.get("LastModifiedDate"),
                    "LastModifiedById": r.get("LastModifiedById"),
                }
            )

            nodes.append(make_node(r["Id"], "SFRole", props))

        return nodes
    
    def build_permission_set_groups(self, psgroups: Dict[str, Any]) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []

        for g in psgroups.get("records", []):
            name = g.get("MasterLabel") or g.get("DeveloperName") or g.get("Id")

            props = _filter_nulls({
                "name": name,
                "MasterLabel": g.get("MasterLabel"),
                "DeveloperName": g.get("DeveloperName"),
                "Status": g.get("Status"),
                "CreatedDate": g.get("CreatedDate"),
                "LastModifiedDate": g.get("LastModifiedDate"),
                "SystemModstamp": g.get("SystemModstamp") or g.get("SystemModStamp"),
            })

            nodes.append(make_node(g["Id"], "SFPermissionSetGroup", props))

        return nodes

    # ============================================================
    # Organization Node
    # ============================================================

    def build_organization(self, instance_url: str) -> Dict[str, Any]:
        """
        Build the Organization node representing the Salesforce org itself.
        System-level permissions (e.g., ModifyAllData) will be edges to this node.
        
        Args:
            instance_url: The Salesforce instance URL (e.g., https://mydomain.my.salesforce.com)
        
        Returns:
            Single Organization node
        """
        # Extract org identifier from instance URL
        from urllib.parse import urlparse
        parsed = urlparse(instance_url)
        hostname = parsed.hostname or "unknown"
        org_subdomain = hostname.split(".")[0]
        
        node_id = f"org::{org_subdomain}"
        
        props = {
            "name": f"Salesforce Organization ({org_subdomain})",
            "subdomain": org_subdomain,
            "instance_url": instance_url,
        }
        
        return make_node(node_id, "SFOrganization", props)

    # ============================================================
    # Group Nodes
    # ============================================================

    def build_groups(self, groups: Dict[str, Any]) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []

        for g in groups.get("records", []):
            name = g.get("Name")
            dev = g.get("DeveloperName")
            display_name = name or dev or g.get("Id")

            props = _filter_nulls(
                {
                    "name": display_name,
                    "Name": name,       
                    "DeveloperName": dev,
                    "Type": g.get("Type"),
                    "RelatedId": g.get("RelatedId"),
                    "OwnerId": g.get("OwnerId"),
                    "DoesIncludeBosses": g.get("DoesIncludeBosses"),
                    "DoesSendEmailToMembers": g.get("DoesSendEmailToMembers"),
                    "CreatedDate": g.get("CreatedDate"),
                    "LastModifiedDate": g.get("LastModifiedDate"),
                    "SystemModstamp": g.get("SystemModstamp") or g.get("SystemModStamp"),
                }
            )

            nodes.append(make_node(g["Id"], "SFGroup", props))

        return nodes

    def build_public_groups(self, groups: Dict[str, Any]) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []

        for g in groups.get("records", []):
            props = _filter_nulls(
                {
                    "name": g.get("Name"),
                    "GroupType": g.get("Type"),
                    "DeveloperName": g.get("DeveloperName"),
                }
            )

            nodes.append(make_node(g["Id"], "SFPublicGroup", props))

        return nodes

    def build_queues(self, queues: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build Queue nodes from Group records with Type='Queue'.
        
        Queues are special groups that can own records (Cases, Leads, etc.).
        QueueSobject junction table defines which object types each queue can own.
        """
        nodes: List[Dict[str, Any]] = []

        for q in queues.get("records", []):
            props = _filter_nulls(
                {
                    "name": q.get("Name"),
                    "GroupType": q.get("Type"),
                    "DeveloperName": q.get("DeveloperName"),
                    "Email": q.get("Email"),
                    "QueueRoutingConfigId": q.get("QueueRoutingConfigId"),
                    "OwnerId": q.get("OwnerId"),
                    "DoesIncludeBosses": q.get("DoesIncludeBosses"),
                    "DoesSendEmailToMembers": q.get("DoesSendEmailToMembers"),
                    "CreatedDate": q.get("CreatedDate"),
                    "LastModifiedDate": q.get("LastModifiedDate"),
                    "SystemModstamp": q.get("SystemModstamp") or q.get("SystemModStamp"),
                }
            )

            nodes.append(make_node(q["Id"], "SFQueue", props))

        return nodes

    def build_connected_apps(self, connected_apps: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build ConnectedApplication nodes - OAuth apps that integrate with Salesforce.
        
        Security properties:
        - AdminApprovedUsersOnly: Requires admin pre-approval (more secure)
        - IsInternal: Internal Salesforce apps vs external integrations
        - FullContentPushNotifications: Can push sensitive data via notifications
        - SessionLevelPolicy: Enhanced session security controls
        - RefreshTokenValidityPeriod: Token lifetime (longer = higher risk)
        """
        nodes: List[Dict[str, Any]] = []

        for app in connected_apps.get("records", []):
            props = _filter_nulls(
                {
                    "name": app.get("Name"),
                    "AdminApprovedUsersOnly": app.get("OptionsAllowAdminApprovedUsersOnly"),
                    "RefreshTokenValidityMetric": app.get("OptionsRefreshTokenValidityMetric"),
                    "HasSessionLevelPolicy": app.get("OptionsHasSessionLevelPolicy"),
                    "IsInternal": app.get("OptionsIsInternal"),
                    "FullContentPushNotifications": app.get("OptionsFullContentPushNotifications"),
                    "MobileSessionTimeout": app.get("MobileSessionTimeout"),
                    "PinLength": app.get("PinLength"),
                    "StartUrl": app.get("StartUrl"),
                    "MobileStartUrl": app.get("MobileStartUrl"),
                    "RefreshTokenValidityPeriod": app.get("RefreshTokenValidityPeriod"),
                    "CreatedById": _norm_sf_id(app.get("CreatedById")),
                    "LastModifiedById": _norm_sf_id(app.get("LastModifiedById")),
                    "CreatedDate": app.get("CreatedDate"),
                    "LastModifiedDate": app.get("LastModifiedDate"),
                    "SystemModstamp": app.get("SystemModstamp") or app.get("SystemModStamp"),
                }
            )

            nodes.append(make_node(app["Id"], "SFConnectedApp", props))

        return nodes

    def build_sobjects(self, sobjects: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build SObject nodes - Salesforce objects (standard & custom).
        
        SObjects are the fundamental data structures in Salesforce:
        - Standard objects: Account, Contact, User, Opportunity, etc.
        - Custom objects: MyCustomObject__c, SecretData__c, etc.
        
        Security-relevant properties:
        - IsEverDeletable: Enables data destruction attacks
        - IsEverCreatable/Updatable: CRUD capabilities
        - InternalSharingModel: Determines base access (Private vs Public)
        - IsCustomSetting: Custom settings may contain credentials
        - KeyPrefix: Used for identifying record IDs (e.g., 001xxx = Account)
        
        Used for:
        - Identifying high-value data targets
        - Mapping CRUD permissions to objects
        - Understanding org data model
        - Finding custom objects with sensitive data
        """
        nodes: List[Dict[str, Any]] = []

        for obj in sobjects.get("records", []):
            # Determine if custom object
            api_name = obj.get("QualifiedApiName", "")
            is_custom = api_name.endswith("__c") or obj.get("NamespacePrefix") is not None

            props = _filter_nulls(
                {
                    "name": api_name,
                    "objectid": obj.get("DurableId"),  # Alternative identifier
                    "Label": obj.get("Label"),
                    "PluralLabel": obj.get("PluralLabel"),
                    "KeyPrefix": obj.get("KeyPrefix"),
                    "IsCustom": is_custom,
                    "IsCustomSetting": obj.get("IsCustomSetting"),
                    "IsCustomizable": obj.get("IsCustomizable"),
                    "DeploymentStatus": obj.get("DeploymentStatus"),
                    "IsEverCreatable": obj.get("IsEverCreatable"),
                    "IsEverUpdatable": obj.get("IsEverUpdatable"),
                    "IsEverDeletable": obj.get("IsEverDeletable"),
                    "IsQueryable": obj.get("IsQueryable"),
                    "IsSearchable": obj.get("IsSearchable"),
                    "InternalSharingModel": obj.get("InternalSharingModel"),
                    "ExternalSharingModel": obj.get("ExternalSharingModel"),
                    "PublisherId": obj.get("PublisherId"),
                    "NamespacePrefix": obj.get("NamespacePrefix"),
                    "LastModifiedById": _norm_sf_id(obj.get("LastModifiedById")),
                    "LastModifiedDate": obj.get("LastModifiedDate"),
                }
            )

            # Use DurableId (API name) as node ID since EntityDefinition.Id is placeholder
            node_id = obj.get("DurableId") or obj.get("QualifiedApiName") or obj.get("Id")
            nodes.append(make_node(node_id, "SFSObject", props))

        return nodes
    def build_fields(self, field_permissions):
        """
        Build SFField nodes - individual fields from FieldPermissions.
        
        Fields are granular components of SObjects that can have independent security:
        - Standard fields: Account.Industry, Contact.Email, etc.
        - Custom fields: SecretData__c.HighlySensitiveField__c, etc.
        
        Security relevance:
        - Field-level security (FLS) is independent of object-level CRUD
        - Sensitive fields (SSN, salary, PII) require FLS to protect
        - Users can have Read on object but not see specific fields
        
        Node modeling:
        - Node ID: Full field API name (e.g., "SecretData__c.HighlySensitiveField__c")
        - Only creates nodes for fields with FLS configured
        - SobjectType property links field to parent object
        
        Used for:
        - Mapping field-level access paths
        - Identifying sensitive field exposure
        - Answering "Who can see HighlySensitiv eField__c?"
        """
        nodes = []
        seen_fields = set()  # Deduplicate fields (multiple perms can reference same field)

        for perm in field_permissions.get("records", []):
            field_name = perm.get("Field")
            sobject_type = perm.get("SobjectType")
            
            if not field_name or field_name in seen_fields:
                continue
            
            seen_fields.add(field_name)
            
            # Parse field name: "SobjectType.FieldName"
            parts = field_name.split(".", 1)
            short_field_name = parts[1] if len(parts) == 2 else field_name
            
            # Determine if custom field
            is_custom = short_field_name.endswith("__c")
            
            props = _filter_nulls(
                {
                    "name": field_name,  # Full API name like "SecretData__c.HighlySensitiveField__c"
                    "objectid": field_name,  # Use field name as ID
                    "FieldName": short_field_name,  # Just the field part
                    "SobjectType": sobject_type,  # Parent object
                    "IsCustom": is_custom,
                }
            )

            nodes.append(make_node(field_name, "SFField", props))

        return nodes
