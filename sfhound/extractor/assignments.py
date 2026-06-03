import requests
from concurrent.futures import ThreadPoolExecutor

class AssignmentExtractor:
    def __init__(self, auth, throttle=None, user_types=None, exclude_username_pattern=None):
        self.auth = auth
        self.api_version = auth.config.get('api_version', 'v56.0')
        self.throttle = throttle
        # Optional user-scoping filters
        self.user_types = user_types  # list[str] or None
        self.exclude_username_pattern = exclude_username_pattern  # str or None

    def query(self, soql):
        access_token, instance_url = self.auth.access_token, self.auth.instance_url
        headers = {"Authorization": f"Bearer {access_token}"}
        if self.throttle is not None:
            headers["Sforce-Query-Options"] = f"batchSize={self.throttle}"

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
    # HELPERS
    # ---------------------------------------

    def _user_filter_conditions(self) -> list[str]:
        """Return validated SOQL WHERE conditions that mirror the user-scoping filters."""
        conditions: list[str] = []
        if self.user_types:
            safe_types = []
            for t in self.user_types:
                t = t.strip()
                if not t.replace("_", "").isalnum():
                    raise ValueError(
                        f"Invalid UserType value '{t}': only alphanumeric characters "
                        "and underscores are allowed."
                    )
                safe_types.append(t)
            quoted = ", ".join(f"'{v}'" for v in safe_types)
            conditions.append(f"UserType IN ({quoted})")  # nosec B608
        if self.exclude_username_pattern:
            pattern = self.exclude_username_pattern
            if "'" in pattern:
                raise ValueError(
                    "exclude_username_pattern must not contain single quotes."
                )
            conditions.append(f"Username NOT LIKE '{pattern}'")  # nosec B608
        return conditions

    def _user_subquery(self) -> str:
        """
        Return a SOQL subquery string ``SELECT Id FROM User WHERE ...`` that reflects
        the active user-scoping filters, or an empty string when no filters are set.
        """
        conditions = self._user_filter_conditions()
        if not conditions:
            return ""
        where = " AND ".join(conditions)
        return f"SELECT Id FROM User WHERE {where}"  # nosec B608

    # ---------------------------------------
    # THESE are the extractor functions
    # ---------------------------------------

    def extract_users(self):
        conditions = self._user_filter_conditions()
        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        soql = f"""
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
        {where_clause}
        """  # nosec B608
        return self.query(soql)

    def extract_permission_set_assignments(self):
        user_sub = self._user_subquery()
        assignee_filter = f"WHERE AssigneeId IN ({user_sub})" if user_sub else ""  # nosec B608
        soql = f"""
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
        {assignee_filter}
        """  # nosec B608
        return self.query(soql)


    def extract_group_members(self):
        user_sub = self._user_subquery()
        # UserOrGroupId may be a User (005...) or a Group (00G...). When a user filter is
        # active, Salesforce does not allow OR combined with a semi-join subselect, so we
        # run two separate queries and merge the results:
        #   1. group-in-group memberships (UserOrGroupId is a Group, not a User)
        #   2. user memberships restricted to the filtered user set
        if user_sub:
            cols = "Id, GroupId, UserOrGroupId, SystemModstamp"
            # Salesforce does not allow LIKE on ID fields, so we use a semi-join against
            # Group to retrieve group-in-group memberships instead of a prefix pattern.
            group_result = self.query(
                f"SELECT {cols} FROM GroupMember WHERE UserOrGroupId IN (SELECT Id FROM Group)"  # nosec B608
            )
            user_result = self.query(
                f"SELECT {cols} FROM GroupMember WHERE UserOrGroupId IN ({user_sub})"  # nosec B608
            )
            seen: set[str] = set()
            merged: list = []
            for row in group_result["records"] + user_result["records"]:
                if row["Id"] not in seen:
                    seen.add(row["Id"])
                    merged.append(row)
            return {
                "records": merged,
                "totalSize": len(merged),
                "done": True,
                "soql": "(merged: group members + filtered users)",
            }
        else:
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
        user_sub = self._user_subquery()
        assignee_filter = f"AND AssigneeId IN ({user_sub})" if user_sub else ""  # nosec B608
        soql = f"""
        SELECT
            Id,
            AssigneeId,
            PermissionSetGroupId,
            SystemModstamp
        FROM PermissionSetAssignment
        WHERE PermissionSetGroupId != null
        {assignee_filter}
        """  # nosec B608
        return self.query(soql)

    def extract_record_owners(self, sobjects_data: dict) -> list:
        """
        Query each custom SObject for distinct OwnerId values to map which users own
        records of which object type. Used to build OwnsRecordsOfObject edges, enabling
        detection of indirect record access via the role hierarchy.

        Filters to custom objects only (QualifiedApiName ending in '__c'), excluding custom
        settings and non-queryable objects. Queries run in parallel across all custom objects
        (max 8 workers). Objects without an OwnerId field or inaccessible to the running user
        are silently skipped.

        Returns a list of {"OwnerId": ..., "SobjectType": ..., "SobjectDurableId": ...} dicts.
        """
        custom_objects = [
            obj for obj in sobjects_data.get("records", [])
            if obj.get("QualifiedApiName", "").endswith("__c")
            and not obj.get("IsCustomSetting")
            and obj.get("IsQueryable")
        ]

        user_sub = self._user_subquery()
        owner_filter = f" WHERE OwnerId IN ({user_sub})" if user_sub else ""  # nosec B608

        def _query_object(obj):
            api_name = obj.get("QualifiedApiName", "")
            durable_id = obj.get("DurableId") or api_name
            try:
                soql = f"SELECT OwnerId FROM {api_name}{owner_filter} GROUP BY OwnerId"  # nosec B608
                batch = self.query(soql)
                return [
                    {"OwnerId": r["OwnerId"], "SobjectType": api_name, "SobjectDurableId": durable_id}
                    for r in batch.get("records", []) if r.get("OwnerId")
                ]
            except Exception:
                return []

        results = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            for partial in executor.map(_query_object, custom_objects):
                results.extend(partial)
        return results