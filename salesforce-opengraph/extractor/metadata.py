# extractor/metadata.py

import requests
from typing import Any, Dict, List, Optional


class MetadataExtractor:
    """
    Metadata pulls via REST API using the existing auth object.

    Expected auth interface:
      - auth.access_token (str)
      - auth.instance_url (str)
      - auth.config (dict) with optional "api_version" (e.g. "v56.0")
    """

    def __init__(self, auth):
        self.auth = auth
        self.api_version = auth.config.get("api_version", "v56.0")

    # -----------------------
    # Low-level REST helpers
    # -----------------------

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.auth.access_token}"}

    def _abs_url(self, path: str) -> str:
        """
        Build a full URL for a Salesforce REST endpoint.

        - If you pass a full URL, it is returned unchanged.
        - If you pass a relative path, it will be prefixed with instance_url.
        """
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.auth.instance_url}{path}"

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generic GET wrapper with better error messages and safe handling
        for Salesforce's occasional 204/empty responses.
        """
        url = self._abs_url(path)
        r = requests.get(url, headers=self._headers(), params=params, timeout=30)

        if r.status_code != 200:
            raise Exception(f"GET failed ({r.status_code}) {url}: {r.text}")

        # Most SF REST endpoints return JSON; guard anyway.
        if not r.text.strip():
            return {}
        return r.json()

    def query(self, soql: str) -> Dict[str, Any]:
        """
        SOQL query with pagination.
        Returns: {"records": [...]} (flattened across pages)
        """
        instance_url = self.auth.instance_url
        headers = self._headers()

        url = f"{instance_url}/services/data/{self.api_version}/query"
        params = {"q": soql}

        all_records: List[Dict[str, Any]] = []

        while True:
            r = requests.get(url, headers=headers, params=params, timeout=30)
            if r.status_code != 200:
                raise Exception(f"SOQL query failed ({r.status_code}): {r.text}")

            data = r.json()
            all_records.extend(data.get("records", []))

            if data.get("done") is True:
                break

            next_url = data.get("nextRecordsUrl")
            if not next_url:
                break

            url = f"{instance_url}{next_url}"
            params = None  # nextRecordsUrl already includes locator

        return {"records": all_records}

    # -----------------------
    # Utility: Describe
    # -----------------------

    def describe_sobject(self, sobject: str) -> Dict[str, Any]:
        """
        Describe an SObject via REST API.

        Uses the canonical full path:
          /services/data/vXX.X/sobjects/<SObject>/describe
        """
        path = f"/services/data/{self.api_version}/sobjects/{sobject}/describe"
        return self.get(path)

    def _queryable_fields_from_describe(self, desc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Returns mapping: fieldName -> fieldDescribe (only queryable fields).
        """
        fields: Dict[str, Dict[str, Any]] = {}
        for f in desc.get("fields", []):
            name = f.get("name")
            if not name:
                continue
            # Salesforce sometimes omits "queryable"; treat missing as True.
            if f.get("queryable", True):
                fields[name] = f
        return fields

    def _select_existing(self, preferred: List[str], available: Dict[str, Any]) -> List[str]:
        return [f for f in preferred if f in available]

    # -----------------------
    # Extractors
    # -----------------------

    def extract_profiles(self) -> Dict[str, Any]:
        """
        Profile metadata with system permissions:
        - Uses describe to get all available fields
        - Includes Permissions* fields for system permission edges
        """
        
        desc = self.describe_sobject("Profile")
        queryable = self._queryable_fields_from_describe(desc)

        # Base fields we want
        preferred: List[str] = [
            "Id",
            "Name",
            "UserLicenseId",
            "UserType",
            "Description",
            "CreatedDate",
            "LastModifiedDate",
            "SystemModstamp",
            # System permission flags (if they exist in your org)
            "PermissionsModifyAllData",
            "PermissionsManageUsers",
            "PermissionsViewSetup",
            "PermissionsCustomizeApplication",
            "PermissionsAuthorApex",
            "PermissionsManageProfilesPermissionsets",
            "PermissionsManagePermissionSets",
            "PermissionsManageConnectedApps",
            "PermissionsManageRoles",
            "PermissionsManageSharing",
            "PermissionsViewAllData",
            "PermissionsManageSessionPermissionSets",
            "PermissionsEditTask",
            "PermissionsEditEvent",
            "PermissionsApiEnabled",
            "PermissionsManageTranslation",
        ]

        fields = self._select_existing(preferred, queryable)

        # Ensure Id is present
        if "Id" in queryable and "Id" not in fields:
            fields.insert(0, "Id")

        soql = "SELECT " + ", ".join(fields) + " FROM Profile"
        return self.query(soql)

    def extract_permission_sets(self) -> Dict[str, Any]:
        """
        PermissionSet metadata:
        - Uses describe to avoid INVALID_FIELD across orgs/editions
        - Pulls Profile.Name so profile-owned PermissionSets can display a human name
        """

        desc = self.describe_sobject("PermissionSet")
        queryable = self._queryable_fields_from_describe(desc)

        # Base fields we want if they exist
        preferred: List[str] = [
            "Id",
            "Name",                 # API name
            "Label",                # human-ish label (but can be systemy for profile-owned)
            "LicenseId",
            "IsOwnedByProfile",
            "ProfileId",
            "Type",
            "HasActivationRequired",
            "IsCustom",
            "CreatedDate",
            "LastModifiedDate",
            "SystemModstamp",
            # Common high-signal system perm flags (only if they exist in your org/API)
            "PermissionsModifyAllData",
            "PermissionsManageUsers",
            "PermissionsViewSetup",
            "PermissionsCustomizeApplication",
            "PermissionsAuthorApex",
            "PermissionsManageProfilesPermissionsets",
            "PermissionsManagePermissionSets",
            "PermissionsManageConnectedApps",
            "PermissionsManageRoles",
            "PermissionsManageSharing",
            "PermissionsManageSessionPermissionSets",
        ]

        fields = self._select_existing(preferred, queryable)

        # Always ensure Id is present
        if "Id" in queryable and "Id" not in fields:
            fields.insert(0, "Id")

        # Relationship fields are NOT in the PermissionSet describe list, so add carefully.
        # These will work in most orgs, but if they error in yours, remove them.
        relationship_fields: List[str] = [
            "Profile.Name",
            "License.Name",
        ]

        # Assemble SOQL
        select_parts = fields + relationship_fields
        soql = "SELECT " + ", ".join(select_parts) + " FROM PermissionSet"

        return self.query(soql)

    def extract_groups(self) -> Dict[str, Any]:
        # Enriched group metadata (works in your org per describe output)
        soql = """
        SELECT
            Id,
            Name,
            DeveloperName,
            Type,
            RelatedId,
            OwnerId,
            DoesIncludeBosses,
            DoesSendEmailToMembers,
            CreatedDate,
            LastModifiedDate,
            SystemModstamp
        FROM Group
        """
        return self.query(soql)
    
    def extract_permission_set_groups(self) -> Dict[str, Any]:
        # Permission Set Groups
        soql = """
        SELECT
            Id,
            MasterLabel,
            DeveloperName,
            Status,
            CreatedDate,
            LastModifiedDate,
            SystemModstamp
        FROM PermissionSetGroup
        """
        return self.query(soql)

    def extract_permission_set_group_components(self) -> Dict[str, Any]:
        # Maps PSG -> PermissionSet
        soql = """
        SELECT
            Id,
            PermissionSetGroupId,
            PermissionSetId,
            CreatedDate,
            LastModifiedDate,
            SystemModstamp
        FROM PermissionSetGroupComponent
        """
        return self.query(soql)

    def extract_user_roles(self) -> Dict[str, Any]:
        """
        UserRole metadata with hierarchy and access level information.
        
        Key fields:
        - ParentRoleId: Role hierarchy (important for privilege escalation analysis)
        - OpportunityAccessForAccountOwner/CaseAccessForAccountOwner/ContactAccessForAccountOwner:
          Data access levels inherited by role members
        - PortalType/PortalRole: Portal user identification
        """
        soql = """
        SELECT 
            Id, 
            Name, 
            DeveloperName, 
            ParentRoleId,
            RollupDescription,
            OpportunityAccessForAccountOwner,
            CaseAccessForAccountOwner,
            ContactAccessForAccountOwner,
            PortalType,
            PortalRole,
            PortalAccountId,
            LastModifiedDate,
            LastModifiedById
        FROM UserRole
        """
        return self.query(soql)

    def extract_queue_sobjects(self) -> Dict[str, Any]:
        """
        QueueSobject junction table: defines which object types each Queue can own.
        
        Critical for privilege escalation analysis:
        - Queue members can access records owned by the Queue
        - This defines the scope (which object types)
        """
        soql = """
        SELECT
            Id,
            QueueId,
            SobjectType,
            CreatedById,
            SystemModstamp
        FROM QueueSobject
        """
        return self.query(soql)

    def extract_connected_apps(self) -> Dict[str, Any]:
        """
        ConnectedApplication: OAuth apps that integrate with Salesforce.
        
        Security considerations:
        - OptionsAllowAdminApprovedUsersOnly: If false, any user can self-authorize (risky)
        - OptionsFullContentPushNotifications: Data exfiltration through push notifications
        - StartUrl/MobileStartUrl: Redirect URLs (phishing/open redirect risk)
        - RefreshTokenValidityPeriod: Token lifetime (longer = higher risk if compromised)
        - OptionsIsInternal: Internal Salesforce apps vs external integrations
        
        Future edges: SetupEntityAccess defines which Profiles/PermissionSets can authorize app
        """
        soql = """
        SELECT
            Id,
            Name,
            CreatedDate,
            CreatedById,
            LastModifiedDate,
            LastModifiedById,
            SystemModstamp,
            OptionsAllowAdminApprovedUsersOnly,
            OptionsRefreshTokenValidityMetric,
            OptionsHasSessionLevelPolicy,
            OptionsIsInternal,
            OptionsFullContentPushNotifications,
            MobileSessionTimeout,
            PinLength,
            StartUrl,
            MobileStartUrl,
            RefreshTokenValidityPeriod
        FROM ConnectedApplication
        """
        return self.query(soql)

    def extract_setup_entity_access(self) -> Dict[str, Any]:
        """
        SetupEntityAccess: Grants Profiles/PermissionSets access to setup entities.
        
        For ConnectedApplications:
        - Defines which Profiles/PermissionSets can authorize the OAuth app
        - Users in those Profiles/PermSets can OAuth login to the app
        - Critical for understanding OAuth access paths
        
        ParentId: References PermissionSet (Profiles have PermissionSet representations)
        SetupEntityId: References the setup entity (ConnectedApp, TabSet, etc.)
        SetupEntityType: Type filter (ConnectedApplication, TabSet, etc.)
        """
        soql = """
        SELECT
            Id,
            ParentId,
            SetupEntityId,
            SetupEntityType,
            SystemModstamp
        FROM SetupEntityAccess
        WHERE SetupEntityType = 'ConnectedApplication'
        """
        return self.query(soql)

    def extract_sobjects(self):
        """
        EntityDefinition: Metadata for all SObjects (standard & custom).
        
        Provides comprehensive object metadata including:
        - QualifiedApiName: The API name (Account, MyCustomObject__c)
        - Label/PluralLabel: Display names
        - KeyPrefix: 3-char ID prefix (001=Account, 003=Contact)
        - IsEverCreatable/Updatable/Deletable: CRUD capability flags
        - InternalSharingModel: Private, Public Read Only, Public Read/Write
        - IsCustomSetting: Custom settings are config objects
        - NamespacePrefix: Null for standard/custom, set for managed packages
        
        Security relevance:
        - Custom objects often contain sensitive data
        - Deletable objects enable data destruction
        - Public sharing models expose data broadly
        - Custom settings may contain credentials/config
        """
        soql = """
        SELECT
            Id,
            DurableId,
            QualifiedApiName,
            NamespacePrefix,
            DeveloperName,
            MasterLabel,
            Label,
            PluralLabel,
            KeyPrefix,
            IsCustomSetting,
            IsCustomizable,
            IsDeprecatedAndHidden,
            DeploymentStatus,
            IsEverCreatable,
            IsEverUpdatable,
            IsEverDeletable,
            IsQueryable,
            IsSearchable,
            InternalSharingModel,
            ExternalSharingModel,
            PublisherId,
            LastModifiedDate,
            LastModifiedById
        FROM EntityDefinition
        WHERE IsDeprecatedAndHidden = false
        """
        return self.query(soql)

    def extract_object_permissions(self):
        """
        ObjectPermissions: CRUD grants from Profiles/PermSets to SObjects.
        
        Junction table linking:
        - ParentId: PermissionSet (Profiles have PermissionSet representations)
        - SobjectType: Object API name (string, not ID)
        
        Permission flags:
        - PermissionsCreate: Can create new records
        - PermissionsRead: Can read records (respecting sharing)
        - PermissionsEdit: Can edit records (respecting sharing)
        - PermissionsDelete: Can delete records (respecting sharing)
        - PermissionsViewAllRecords: View ALL records (bypass sharing)
        - PermissionsModifyAllRecords: Edit/Delete ALL records (bypass sharing)
        
        Security relevance:
        - ViewAll/ModifyAll bypass sharing rules (super user perms)
        - Delete permissions enable data destruction
        - Tracks exact CRUD capabilities per Profile/PermSet
        - Critical for answering "Who can delete SecretData__c?"
        """
        soql = """
        SELECT
            Id,
            ParentId,
            SobjectType,
            PermissionsCreate,
            PermissionsRead,
            PermissionsEdit,
            PermissionsDelete,
            PermissionsViewAllRecords,
            PermissionsModifyAllRecords,
            SystemModstamp
        FROM ObjectPermissions
        """
        return self.query(soql)

    def extract_field_permissions(self):
        """
        FieldPermissions: Field-Level Security (FLS) grants from Profiles/PermSets to individual fields.
        
        Junction table linking:
        - ParentId: PermissionSet (Profiles have PermissionSet representations)
        - SobjectType: Object API name (e.g., "Account", "SecretData__c")
        - Field: Full field API name (e.g., "Account.Industry", "SecretData__c.HighlySensitiveField__c")
        
        Permission flags:
        - PermissionsEdit: Field is visible AND editable (read+write)
        - PermissionsRead: Field is visible (read-only if Edit is False)
        
        Security relevance:
        - Controls access to sensitive fields (SSN, salaries, PII, secrets)
        - Independent of object-level CRUD (can have Read on object but not field)
        - Critical for answering "Who can see HighlySensitiveField__c?"
        
        Edge modeling:
        - Profile/PermissionSet -[IsVisible]-> Field (when PermissionsEdit = True)
        - Profile/PermissionSet -[ReadOnly]-> Field (when PermissionsRead = True AND PermissionsEdit = False)
        """
        soql = """
        SELECT
            Id,
            ParentId,
            SobjectType,
            Field,
            PermissionsEdit,
            PermissionsRead,
            SystemModstamp
        FROM FieldPermissions
        """
        return self.query(soql)