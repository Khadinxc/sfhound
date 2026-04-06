import requests

class AssignmentExtractor:
    def __init__(self, auth):
        self.auth = auth
        self.api_version = auth.config.get('api_version', 'v56.0')

    def query(self, soql):
        access_token, instance_url = self.auth.access_token, self.auth.instance_url
        headers = {"Authorization": f"Bearer {access_token}"}

        url = f"{instance_url}/services/data/{self.api_version}/query"
        params = {"q": soql}

        all_records = []
        total_size = None

        while True:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            if response.status_code != 200:
                raise Exception(f"SOQL query failed: {response.text}")

            data = response.json()

            if total_size is None:
                total_size = data.get("totalSize")

            all_records.extend(data.get("records", []))

            if data.get("done") is True:
                break

            next_url = data.get("nextRecordsUrl")
            if not next_url:
                break

            url = f"{instance_url}{next_url}"
            params = None

        return {
            "records": all_records,
            "totalSize": total_size,
            "done": True,
            "soql": soql,
        }

    # ---------------------------------------
    # THESE are the extractor functions
    # ---------------------------------------

    def extract_users(self):
        soql = """
        SELECT
            Id,
            Name,
            Username,
            Email,
            IsActive,
            UserType,

            ProfileId,
            Profile.Name,

            UserRoleId,
            UserRole.Name,

            ManagerId,
            Manager.Name,

            FederationIdentifier,
            Alias,

            TimeZoneSidKey,
            LocaleSidKey,
            LanguageLocaleKey,
            EmailEncodingKey,

            LastLoginDate,
            LastPasswordChangeDate,
            CreatedDate,
            LastModifiedDate
        FROM User
        """
        return self.query(soql)

    def extract_permission_set_assignments(self):
        soql = """
        SELECT
        Id,
        AssigneeId,
        PermissionSetId,
        PermissionSet.Name,
        PermissionSet.Label,
        ExpirationDate,
        IsActive,
        SystemModstamp
        FROM PermissionSetAssignment
        """
        return self.query(soql)


    def extract_group_members(self):
        soql = """
        SELECT
            Id,
            GroupId,
            UserOrGroupId,
            SystemModstamp
        FROM GroupMember
        """
        return self.query(soql)
    
    def extract_permission_set_groups(self) -> dict[str, any]:
        soql = """
        SELECT Id, DeveloperName, MasterLabel, Status, CreatedDate, LastModifiedDate, SystemModstamp
        FROM PermissionSetGroup
        """
        return self.query(soql)

    def extract_permission_set_group_components(self) -> dict[str, any]:
        # Links PermissionSetGroupId -> PermissionSetId
        soql = """
        SELECT Id, PermissionSetGroupId, PermissionSetId, CreatedDate, LastModifiedDate, SystemModstamp
        FROM PermissionSetGroupComponent
        """
        return self.query(soql)
    
    def extract_permission_set_group_assignments(self):
        soql = """
        SELECT
            Id,
            AssigneeId,
            PermissionSetGroupId,
            SystemModstamp
        FROM PermissionSetAssignment
        WHERE PermissionSetGroupId != null
        """
        return self.query(soql)

    def extract_record_owners(self, sobjects_data: dict) -> list:
        """
        Query each custom SObject for distinct OwnerId values to map which users own
        records of which object type. Used to build OwnsRecordsOfObject edges, enabling
        detection of indirect record access via the role hierarchy.

        Filters to custom objects only (QualifiedApiName ending in '__c'), excluding custom
        settings and non-queryable objects. Objects without an OwnerId field or inaccessible
        to the running user are silently skipped.

        Returns a list of {"OwnerId": ..., "SobjectType": ..., "SobjectDurableId": ...} dicts.
        """
        results = []
        for obj in sobjects_data.get("records", []):
            api_name = obj.get("QualifiedApiName", "")
            durable_id = obj.get("DurableId") or api_name

            # Limit to custom data objects only
            if not api_name.endswith("__c"):
                continue
            if obj.get("IsCustomSetting"):
                continue
            if not obj.get("IsQueryable"):
                continue

            try:
                soql = f"SELECT OwnerId FROM {api_name} GROUP BY OwnerId"
                batch = self.query(soql)
                for r in batch.get("records", []):
                    owner_id = r.get("OwnerId")
                    if owner_id:
                        results.append({
                            "OwnerId": owner_id,
                            "SobjectType": api_name,
                            "SobjectDurableId": durable_id,
                        })
            except Exception:
                # Object lacks OwnerId field, has zero records,
                # or running user lacks read permission — skip silently.
                pass

        return results