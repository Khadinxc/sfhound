from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from bhopengraph.Edge import Edge as _BHEdge
from bhopengraph.Properties import Properties as _BHProperties

_PRIMITIVE_TYPES = (str, int, float, bool)


def _make_edge(
    start: str,
    end: str,
    kind: str,
    properties: Optional[Dict[str, Any]] = None,
) -> _BHEdge:
    """
    Create a bhopengraph.Edge from sfhound collector data.

    - Normalises start/end IDs (strip + uppercase)
    - Drops None and non-primitive property values before passing to
      bhopengraph.Properties (which only accepts str/int/float/bool and
      homogeneous primitive lists — the rich context strings in this module
      are all str so they pass through cleanly)
    - Returns a bhopengraph.Edge ready for graph.add_edge_without_validation()
    """
    start = _norm_sf_id(start) or start
    end = _norm_sf_id(end) or end
    bh_props: Optional[_BHProperties] = None
    if properties:
        clean = {
            k: v for k, v in properties.items()
            if v is not None and isinstance(v, _PRIMITIVE_TYPES)
        }
        if clean:
            bh_props = _BHProperties(**clean)
    return _BHEdge(start, end, kind, bh_props)


def _norm_sf_id(v: str | None) -> str | None:
    if not v:
        return v
    return v.strip().upper()

# -------------------------
# Edge kind normalization
# -------------------------

class EdgeKinds:
    """
    BloodHound generic ingest prefers PascalCase relationship names.
    These constants ensure your collector emits ingest-ready data.
    """

    # Direct identity/assignment
    ASSIGNED_PROFILE = "AssignedProfile"
    ASSIGNED_PERMISSION_SET = "AssignedPermissionSet"
    ASSIGNED_PERMISSION_SET_GROUP = "AssignedPermissionSetGroup"

    # Role relationships
    HAS_ROLE = "HasRole"
    INHERITS_ROLE = "InheritsRole"

    # Groups
    MEMBER_OF_GROUP = "MemberOfGroup"
    HAS_MEMBER = "HasMember"
    INCLUDES_PERMISSION_SET = "IncludesPermissionSet"

    # Profile-owned PermissionSets (i.e., the PermissionSet record that represents the Profile)
    HAS_PERMISSION_SET = "HasPermissionSet"

    # Queue relationships
    CAN_OWN_OBJECT = "CanOwnObject"

    # Record ownership
    OWNS_RECORDS_OF_OBJECT = "OwnsRecordsOfObject"

    # Creation/ownership
    CREATED_BY = "CreatedBy"

    # ConnectedApp authorization
    CAN_AUTHORIZE = "CanAuthorize"

    # SObject CRUD permissions (ObjectPermissions)
    CAN_CREATE = "CanCreate"
    CAN_READ = "CanRead"
    CAN_EDIT = "CanEdit"
    CAN_DELETE = "CanDelete"
    CAN_VIEW_ALL = "CanViewAll"          # ViewAllRecords - bypass sharing
    CAN_MODIFY_ALL = "CanModifyAll"      # ModifyAllRecords - bypass sharing

    # Field-Level Security (FLS) permissions (FieldPermissions)
    IS_VISIBLE = "IsVisible"              # Field visible and editable (PermissionsEdit = True)
    READ_ONLY = "ReadOnly"                # Field visible but read-only (PermissionsRead = True, PermissionsEdit = False)


# -------------------------
# System Permission Context
# -------------------------
# Contextual descriptions and impact statements for high-risk system permissions.
# These properties are added to the edge between a Profile/PermissionSet and the
# Organization node so auditors can see the security significance directly in the GUI.
#
# Sources:
#   - Salesforce Help: "User Permissions" (admin_userperms)
#     https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
#   - Salesforce Security Guide: "Administrative Permissions"
#     https://help.salesforce.com/s/articleView?id=sf.permissions_about_perms_and_accts.htm
#   - Salesforce Apex Developer Guide: "Apex Security and Sharing"
#     https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_security_sharing_chapter.htm
#
# Property keys are PascalCase per OpenGraph schema requirements.
# To update or extend descriptions, add/modify entries below and re-run the collector.

SYSTEM_PERMISSION_CONTEXT: Dict[str, Dict[str, str]] = {
    # Tier Zero
    # Source: Salesforce Help "User Permissions" - ModifyAllData permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows reading, editing, creating, deleting, approving, and transferring ALL
    # records in the org, completely bypassing record-level and field-level security.
    "ModifyAllData": {
        "General": (
            "Grants read, create, edit, delete, approve, and transfer access to every record "
            "in the organisation, regardless of record ownership, sharing rules, or object-level "
            "permissions. When enabled as a system permission it implicitly grants Modify All Records "
            "and View All Records on every object in the org. Disabling ModifyAllData does NOT "
            "automatically remove those per-object grants — they must be cleared manually. "
            "Note: this permission does NOT override field-level security; users must still hold "
            "individual field permissions or the View All Fields object permission to access "
            "restricted fields."
        ),
        "AbuseInfo": (
            "Highest-risk permission in Salesforce. A holder can exfiltrate the entire org dataset, "
            "destroy or falsify any record, and bypass all sharing and ownership controls. Equivalent to "
            "database DBA access. FLS remains the only platform-enforced data boundary this permission "
            "does not dissolve — fields without an explicit grant or View All Fields are still hidden. "
            "Treat any assignment as critical and review immediately."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1565 - Data Manipulation | "
            "Salesforce Help - User Profile Permission Descriptions: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm | "
            "Salesforce Help - Modify All Data Permission: https://help.salesforce.com/s/articleView?id=sf.users_profiles_modifyalldata.htm | "
            "Salesforce Help - View All and Modify All Permissions Overview: https://help.salesforce.com/s/articleView?id=sf.users_profiles_view_all_mod_all.htm"
        ),
        "RemediationInfo": (
            "Restrict to break-glass System Administrator accounts only. Remove from all functional profiles and permission sets. Implement a quarterly formal access review; consider time-limited permission sets for break-glass activation. Audit current holders via SOQL: SELECT AssigneeId FROM PermissionSetAssignment WHERE PermissionSet.PermissionsModifyAllData = true."
        ),
        "OPSEC": (
            "ModifyAllData use is not individually logged per record in standard audit. Setup Audit Trail records profile/permset changes that grant or remove this permission, not the data operations performed under it. Bulk API operations are visible in Event Monitoring API usage logs if licensed, but individual record reads and writes appear as normal user activity. Assume any operation performed under this permission is forensically silent in default org configurations."
        ),
    },

    # Tier Zero
    # Source: Salesforce Help "User Permissions" - ManageUsers permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows creating, editing, deactivating, unlocking, and resetting passwords for
    # all user accounts, including System Administrator profiles.
    "ManageUsers": {
        "General": (
            "Allows creating new user accounts, editing existing profiles and roles, resetting "
            "passwords, unlocking accounts, and deactivating users across the entire organisation, "
            "including users with System Administrator profiles."
        ),
        "AbuseInfo": (
            "Direct privilege escalation vector. An attacker can create a new System Administrator "
            "account, reset the password of an existing admin to gain access, or lock out legitimate "
            "admins. Effectively grants the ability to fully control who can access the org."
        ),
        "References": (
            "MITRE ATT&CK: T1136 - Create Account / T1098 - Account Manipulation | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Restrict to named Identity Governance or IT Operations accounts; avoid granting via permission set to generic profiles. Require an approval workflow for user provisioning and for password resets on privileged accounts. Monitor Setup Audit Trail for user creation, profile reassignment, and password reset events. Disable for all non-administrative accounts and review holders monthly."
        ),
        "OPSEC": (
            "User creation sends a welcome email to the new address, alerting the mailbox owner. Password resets trigger notification emails to the reset account. All user record changes are logged in Setup Audit Trail under UserManagement event type. To avoid triggering MFA notifications on an existing account, attackers may prefer creating a new parallel account rather than resetting a live account's password."
        ),
    },

    # Tier Zero
    # Source: Salesforce Help "User Permissions" - ManageProfilesPermissionsets permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows creating, editing, and deleting profiles and permission sets, including
    # assigning dangerous system permissions such as ModifyAllData to any principal.
    "ManageProfilesPermissionsets": {
        "General": (
            "Allows creating, editing, cloning, and deleting profiles and permission sets. "
            "Includes the ability to grant any system permission - such as ModifyAllData or "
            "ManageUsers - to any profile or permission set in the organisation."
        ),
        "AbuseInfo": (
            "Indirect privilege escalation to full org control. A holder can edit their own profile "
            "or permission set to add ModifyAllData, effectively granting themselves superuser access. "
            "Can also silently elevate other accounts. Treat as equivalent to ModifyAllData in risk."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1548 - Abuse Elevation Control Mechanism | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Restrict to a minimal change-control team; enforce peer review via a change management system before any profile or permission set modification in production. Maintain separate sandbox environments for development and testing. Conduct monthly permission set audits: compare profile and permission set configurations against a known-good baseline to detect unauthorised privilege additions."
        ),
        "OPSEC": (
            "All profile and permission set edits are captured in Setup Audit Trail with the changed field names. Changes to a profile affect ALL users on that profile simultaneously, but the audit log entry references only the profile name, not the individual affected users. Bulk permission additions via the Metadata API may appear as a single deployment event rather than individual per-permission audit entries, reducing the signal-to-noise ratio."
        ),
    },

    # Tier Zero
    # Source: Salesforce Apex Developer Guide - "Apex Security and Sharing"
    # https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_security_sharing_chapter.htm
    # Source: Salesforce Help "User Permissions" - AuthorApex permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows writing, saving, compiling, and executing Apex classes, triggers,
    # and anonymous Apex code. Apex runs server-side and can use 'without sharing'.
    "AuthorApex": {
        "General": (
            "Allows writing, compiling, and deploying Apex classes, triggers, and test code. "
            "Also enables execution of anonymous Apex via the Developer Console or Tooling API. "
            "Apex code can be written with 'without sharing' to bypass all record-visibility controls."
        ),
        "AbuseInfo": (
            "Enables arbitrary server-side code execution within the org context. An attacker can "
            "write Apex triggers that silently exfiltrate all data via HTTP callouts, create backdoor "
            "admin accounts, or mass-modify records. Code runs as the executing user and can bypass "
            "sharing rules when annotated 'without sharing'. Treat as remote code execution (RCE)."
        ),
        "References": (
            "MITRE ATT&CK: T1059 - Command and Scripting Interpreter / T1105 - Ingress Tool Transfer | "
            "Salesforce Developer Docs: https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_security_sharing_chapter.htm | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Restrict AuthorApex to developers operating in sandbox environments. All production Apex deployments must pass a code review and change approval process. Enforce source control (SFDX/Git) for all Apex code. Require a Named Credential or Remote Site Setting approval process to control permitted external callout endpoints and prevent data exfiltration channels from being introduced via code change."
        ),
        "OPSEC": (
            "Apex deployments are recorded in Setup Audit Trail and in the Deployment Status UI. Anonymous Apex execution is captured in the ExecuteAnonymousApex event log but only if Event Monitoring is licensed. HTTP callouts made by Apex appear in API Callout event logs only when Event Monitoring is enabled; they are invisible to the standard audit trail. Attackers can embed exfiltration logic in Apex triggers that fires on normal record saves, producing no distinctive audit signal beyond the trigger execution itself."
        ),
    },

    # Tier Zero
    # Source: Salesforce Help "User Permissions" - CustomizeApplication permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows modifying the application structure: custom objects, fields, workflow rules,
    # process builder flows, validation rules, sharing rules, and security settings.
    "CustomizeApplication": {
        "General": (
            "Allows creating and modifying custom objects, fields, page layouts, workflow rules, "
            "process automations, validation rules, sharing rules, and other application metadata. "
            "Includes the ability to change organisation-wide default (OWD) sharing settings."
        ),
        "AbuseInfo": (
            "Can be used to install persistent data-harvesting logic via workflow email alerts or "
            "outbound messages, weaken sharing settings to expose records, add hidden formula fields "
            "to capture sensitive data, or create automation that escalates privileges. Can also "
            "modify validation rules to disable security controls or tamper with audit trails."
        ),
        "References": (
            "MITRE ATT&CK: T1565 - Data Manipulation / T1078 - Valid Accounts | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Enforce a sandbox-to-production pipeline for all metadata changes with mandatory peer review. Restrict to certified administrators with formal change management accountability. Treat Organisation-Wide Default sharing changes as Tier Zero events requiring CISO sign-off. Use Metadata API snapshots and scheduled comparisons to detect unauthorised schema changes between review cycles."
        ),
        "OPSEC": (
            "Most metadata changes are recorded in Setup Audit Trail at the object or rule level, not the field value level. Small automation additions — such as a new Process Builder action, a hidden formula field, or a minor validation rule change — may not trigger security team alerting unless active metadata change monitoring is in place. OWD changes are logged with before and after values and represent the highest-visibility event in this category."
        ),
    },

    # Tier Zero
    # Source: Salesforce Help "User Permissions" - ManageSharing permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows creating and modifying sharing rules, manual shares, and
    # organisation-wide default (OWD) sharing settings for all objects.
    "ManageSharing": {
        "General": (
            "Allows creating, editing, and deleting sharing rules for all objects, as well as "
            "performing manual shares on any record. Also enables modification of "
            "Organisation-Wide Default (OWD) sharing settings that govern baseline record access."
        ),
        "AbuseInfo": (
            "Can be used to widen record visibility across the entire org - for example, "
            "changing Private OWD settings to Public Read/Write, exposing all records to all users. "
            "Can also create targeted sharing rules to grant an attacker-controlled account access "
            "to sensitive records without detection. Effectively undermines the entire sharing model."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1565 - Data Manipulation | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Restrict OWD sharing changes to a designated senior administrator team; require dual approval for any OWD modification. Audit all sharing rule additions and deletions monthly via Setup Audit Trail. Review organisation-wide defaults against the data classification policy annually. Remove ManageSharing from all non-administrative profiles immediately."
        ),
        "OPSEC": (
            "Sharing rule additions and OWD changes are logged in Setup Audit Trail. Manual shares on individual records create Share records (AccountShare, ContactShare, etc.) that are queryable via SOQL but do not appear in Setup Audit Trail, leaving no administrative log of targeted record sharing. This makes low-volume manual sharing the most forensically quiet escalation method available under this permission."
        ),
    },

    # Source: Salesforce Help "User Permissions" - ViewSetup permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows read-only access to Setup pages, including user lists, profiles,
    # permission sets, connected apps, and security configurations.
    "ViewSetup": {
        "General": (
            "Provides read-only access to Setup and Configuration pages, including the user list, "
            "profiles, permission sets, connected app configurations, security health checks, "
            "audit trails, and certificate and key management."
        ),
        "AbuseInfo": (
            "Enables reconnaissance of the entire org security configuration without making changes. "
            "An attacker can enumerate all users, identify high-value admin accounts, map permission "
            "boundaries, discover connected apps and integration secrets, and read audit logs to "
            "understand detection capabilities before escalating. Critical for attacker situational awareness."
        ),
        "References": (
            "MITRE ATT&CK: T1087 - Account Discovery / T1518 - Software Discovery | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Grant ViewSetup only when a clear business justification exists; it is not required for standard user operations. Evaluate whether Delegated Administration scopes cover the use case without requiring full Setup access. Audit permission holders quarterly and remove ViewSetup from all standard user profiles."
        ),
        "OPSEC": (
            "ViewSetup-based reconnaissance leaves no trace in Setup Audit Trail. There is no audit log entry for reading setup pages, viewing user lists, or inspecting profile configurations. Event Monitoring Lightning page view events (if licensed) may record Setup page visits, but this is not enabled by default. Treat any holder as capable of performing silent full-org enumeration."
        ),
    },

    # Source: Salesforce Help "User Permissions" - ManageRoles permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows creating, editing, and deleting roles in the role hierarchy,
    # which controls record visibility and subordinate data access.
    "ManageRoles": {
        "General": (
            "Allows creating, editing, renaming, and deleting roles in the role hierarchy. "
            "The role hierarchy controls which users can view records owned by users below "
            "them in the hierarchy, including automatic sharing of child-role records upward."
        ),
        "AbuseInfo": (
            "Role hierarchy manipulation is a covert privilege escalation path. An attacker can "
            "insert a controlled account above target roles to gain read access to all subordinate "
            "records, or reassign a user to a higher role to expand their data access without "
            "modifying profiles or permission sets. Changes may go unnoticed in routine permission reviews."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1548 - Abuse Elevation Control Mechanism | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Restrict to a named Salesforce Administrator role; require change management approval for any role hierarchy changes. Document the current role hierarchy and review annually against the organisational chart. Configure Setup Audit Trail alerting for role creation, deletion, and user role reassignment events. Remove ManageRoles from all non-IT accounts."
        ),
        "OPSEC": (
            "Role creation, editing, and deletion are logged in Setup Audit Trail. Changes to a user's UserRoleId are also logged as UserManagement events. However, role hierarchy manipulation changes effective record visibility for all affected users immediately without generating per-record or per-user share change events. Detection requires monitoring Setup Audit Trail for role-related changes rather than data access events."
        ),
    },

    # Source: Salesforce Help "User Permissions" - ViewAllData permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Grants read-only access to every record in the organisation regardless of
    # record ownership, sharing rules, or OWD settings. Does not include write access.
    "ViewAllData": {
        "General": (
            "Grants read access to every record in the organisation regardless of record ownership, "
            "sharing rules, role hierarchy, or Organisation-Wide Default (OWD) settings. "
            "Does not grant create, edit, or delete capabilities."
        ),
        "AbuseInfo": (
            "Enables complete data exfiltration without write risk. A holder can read every record "
            "across all objects — including sensitive PII, financial data, credentials stored in "
            "custom objects, and confidential communications — bypassing all record-level visibility "
            "controls. Treat any assignment as a critical data-exposure finding."
        ),
        "References": (
            "MITRE ATT&CK: T1530 - Data from Cloud Storage / T1213 - Data from Information Repositories | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Remove ViewAllData from all non-system-administrator profiles and permission sets; document and justify any exception with a named business owner and review date. Treat any human account with ViewAllData as Tier Zero requiring privileged access management (PAM) controls. Prefer object-level CanViewAll for cases where only specific object access is needed."
        ),
        "OPSEC": (
            "ViewAllData does not generate per-record read events in standard Salesforce logs. Bulk data extraction via the Bulk API or Workbench is logged in API usage event logs but is indistinguishable from legitimate admin data operations. Event Monitoring with Field Audit Trail, Data Export, or Report event types (additional licence required) is the only mechanism for detecting ViewAllData-based exfiltration in the default org."
        ),
    },

    # Source: Salesforce Help "User Permissions" - ApiEnabled permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Required for any programmatic access to Salesforce via REST, SOAP, Bulk,
    # Metadata, or Tooling APIs. Without this permission, API calls are rejected.
    "ApiEnabled": {
        "General": (
            "Grants the ability to interact with Salesforce via REST, SOAP, Bulk, Metadata, "
            "and Tooling APIs. Required for all programmatic integration, automation, and "
            "developer tooling access. Without it, all API-based requests are rejected."
        ),
        "AbuseInfo": (
            "Prerequisite for all automated and scripted attacks against the org. An attacker "
            "with API credentials and this permission can enumerate users, extract bulk data via "
            "the Bulk API, deploy Apex via the Metadata API, and interact with all other APIs "
            "without using the browser-based UI. Any compromised account with API Enabled is "
            "immediately exploitable for large-scale automated operations."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1190 - Exploit Public-Facing Application | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Restrict API access to profiles and permission sets that have documented integration or development requirements. For standard end-user profiles, disable ApiEnabled. Enforce IP range restrictions and Connected App policies for all API-enabled accounts. Monitor for anomalous API usage volumes and off-hours access via Event Monitoring."
        ),
        "OPSEC": (
            "API authentication events appear in LoginHistory, providing per-login visibility. Individual API operations (SOQL queries, DML) are only logged with Event Monitoring (SOAP API Usage, REST API Usage events), which requires a Performance or Unlimited Edition licence. On standard edition orgs, there is no per-call API visibility beyond login events, allowing large-scale data extraction to proceed silently post-authentication."
        ),
    },

    # Source: Salesforce Help "User Permissions" - ManageTranslation permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows managing the Translation Workbench, including enabling languages,
    # exporting/importing translation files, and overriding field and UI labels.
    "ManageTranslation": {
        "General": (
            "Allows enabling and disabling languages in the Translation Workbench, exporting "
            "translation files, importing translated content, and overriding field labels, "
            "picklist values, custom button names, and other UI strings organisation-wide."
        ),
        "AbuseInfo": (
            "Can be abused for social engineering and UI manipulation. An attacker can rename "
            "field labels, custom object names, or button text to mislead users into entering "
            "sensitive data into attacker-controlled fields or taking unintended actions. "
            "Translation exports may also leak metadata about custom objects and field names "
            "not otherwise visible in the API schema, aiding further reconnaissance."
        ),
        "References": (
            "MITRE ATT&CK: T1565 - Data Manipulation / T1036 - Masquerading | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Restrict ManageTranslation to a dedicated localisation team account; do not include it in general administrator profiles. Require review of translation file contents before import to detect label tampering. Audit all translation imports and exports via Setup Audit Trail. Remove from profiles where localisation is not an active function."
        ),
        "OPSEC": (
            "Translation imports and exports are logged in Setup Audit Trail. Label changes take effect immediately for all users on the affected locale without any per-user notification or visible change indicator. Renaming a field label or button to something deceptive is effectively invisible to end users unless they compare the current UI against a baseline or notice the discrepancy through use."
        ),
    },

    # Source: Salesforce Help "User Permissions" - EditTask permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows editing Tasks owned by other users (beyond the standard ownership model
    # where a user can only edit their own tasks). Access remains SHARING-GATED:
    # the user can only edit tasks already visible to them via OWD, role hierarchy,
    # or sharing rules — it does not grant visibility to hidden tasks.
    "EditTask": {
        "General": (
            "Allows editing Task records owned by other users. By default, users can only edit "
            "Tasks they own. This permission overrides that ownership restriction and permits "
            "modification of any Task record that is already visible to the user via sharing "
            "rules, role hierarchy, or Organisation-Wide Default (OWD) settings. It does not "
            "independently grant visibility to tasks the user cannot already see."
        ),
        "AbuseInfo": (
            "Sharing-gated: blast radius is limited to tasks already visible via the org's "
            "sharing model. When combined with ViewAllData, the user can edit every task in the "
            "org, enabling complete activity-history falsification. On its own, it allows "
            "tampering with activity records belonging to visible peers, altering due dates, "
            "descriptions, and completion status. On orgs where Tasks track compliance, approvals, "
            "or case management, this can be used to forge audit trails without broader write access."
        ),
        "References": (
            "MITRE ATT&CK: T1565 - Data Manipulation / T1070 - Indicator Removal | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Evaluate whether cross-user Task editing is genuinely required by any user role; most orgs do not need it. Remove from standard user profiles and grant via a targeted, named permission set only when a documented workflow requires it. Review permission holders quarterly and enable Field History Tracking on Task.Status and Task.Description for orgs where activity log integrity is compliance-relevant."
        ),
        "OPSEC": (
            "Individual Task edits are not recorded in Setup Audit Trail. Changes appear only in the record's standard LastModifiedBy and SystemModstamp fields. There is no dedicated audit event for cross-user task modification. Detection relies on querying Task records for cases where LastModifiedById differs from OwnerId, which is not surfaced in standard security dashboards."
        ),
    },

    # Source: Salesforce Help "User Permissions" - EditEvent permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Allows editing Event (calendar activity) records owned by other users,
    # overriding the standard per-owner edit restriction on calendar items.
    # Access remains SHARING-GATED: Events follow a ControlledByParent OWD model,
    # meaning visibility is governed by the parent record's sharing rules.
    "EditEvent": {
        "General": (
            "Allows editing Event (calendar activity) records owned by other users. By default, "
            "users can only edit Events they own. This permission overrides that ownership "
            "restriction and permits modification of any Event record already visible to the user. "
            "Events typically follow a ControlledByParent OWD model — visibility is tied to the "
            "parent record (Contact, Account, Opportunity, etc.) rather than a standalone policy."
        ),
        "AbuseInfo": (
            "Sharing-gated: blast radius is limited to events already visible through the parent "
            "record's sharing model. When combined with ViewAllData, the user can edit every "
            "calendar event in the org, enabling complete activity-log falsification. On its own, "
            "it allows tampering with meeting records, interview schedules, and compliance-relevant "
            "events belonging to visible peers, altering times, invitees, and descriptions. "
            "Can be exploited to remove evidence of attacker activity from audit-visible event logs."
        ),
        "References": (
            "MITRE ATT&CK: T1565 - Data Manipulation / T1070 - Indicator Removal | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Restrict EditEvent to profiles and permission sets with a documented business requirement such as executive assistant or administrative scheduling workflows. Remove from standard user and partner profiles. Review holders quarterly. Enable Field History Tracking on key Event fields (Subject, StartDateTime, EndDateTime) in orgs where calendar integrity is compliance-relevant."
        ),
        "OPSEC": (
            "Event record edits appear only in the standard LastModifiedBy and SystemModstamp audit fields on the Event object and are not logged in Setup Audit Trail. There is no platform event or streaming notification for cross-user event modification by default. Detection requires proactive querying of Event records for LastModifiedById != OwnerId patterns, which is not a default security monitoring posture."
        ),
    },
}


# -------------------------
# Object Permission Context
# -------------------------
# Contextual descriptions and impact statements for object-level CRUD permissions.
# These properties are added to CanCreate/CanRead/CanEdit/CanDelete/CanViewAll/CanModifyAll
# edges between a Profile/PermissionSet and an SObject node.
#
# Sources:
#   - Salesforce Help: "Object Permissions" (admin_userperms)
#     https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
#   - Salesforce Security Guide: "Object-Level Security"
#     https://help.salesforce.com/s/articleView?id=sf.sf_permissions_overview.htm
#   - Salesforce Developer Guide: "Understanding Sharing"
#     https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_classes_perms_enforcing.htm
#
# Property keys are PascalCase per OpenGraph schema requirements.
# To update or extend descriptions, add/modify entries below and re-run the collector.

OBJECT_PERMISSION_CONTEXT: Dict[str, Dict[str, str]] = {
    # Source: Salesforce Help "Object Permissions" - Read permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Grants the ability to view records of this object type, subject to
    # sharing rules, role hierarchy, and OWD settings.
    "CanRead": {
        "General": (
            "Grants the ability to view records of this object type. Access is still subject "
            "to record-level sharing controls (OWD, sharing rules, role hierarchy). "
            "Without Read, the object is completely invisible to the user."
        ),
        "AbuseInfo": (
            "Baseline data access. For sensitive objects (e.g. custom credential stores, PII objects) "
            "Read access alone enables data exfiltration of all records the user can see. "
            "When combined with Public OWD or broad sharing rules this may expose the entire object dataset."
        ),
        "References": (
            "MITRE ATT&CK: T1530 - Data from Cloud Storage / T1213 - Data from Information Repositories | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Apply a data classification model to all SObjects; restrict CanRead on sensitive objects (PII, financial records, credential stores) to profiles and permission sets with a documented business need. Review object permission grants quarterly via the Permission Set and Profile object permission matrices. Use CanViewAll only when cross-user read access is genuinely required."
        ),
        "OPSEC": (
            "Object-level CRUD permissions are not logged when a user reads a record in standard audit. Read events appear only with Event Monitoring (Field Audit Trail) which requires an additional licence. Profile and permission set changes that grant CanRead are logged in Setup Audit Trail. Assume any holder of CanRead on a sensitive object can exfiltrate all accessible records silently in default org configurations."
        ),
    },

    # Source: Salesforce Help "Object Permissions" - Create permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Grants the ability to create new records of this object type.
    # Implicitly requires Read to be useful.
    "CanCreate": {
        "General": (
            "Grants the ability to create new records of this object type. "
            "The user becomes the owner of any records they create, giving them full "
            "access to those records regardless of OWD settings."
        ),
        "AbuseInfo": (
            "Enables data injection and record fabrication (e.g. creating fake User or Contact records). "
            "An attacker can create records that trigger automated processes (workflows, Apex triggers) "
            "as a side-channel. Record ownership after creation grants full access to the new record "
            "irrespective of sharing rules, which can be leveraged for further escalation."
        ),
        "References": (
            "MITRE ATT&CK: T1565 - Data Manipulation / T1059 - Command and Scripting Interpreter | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Limit record creation to profiles and permission sets with an operational need. For sensitive objects, consider Apex trigger validation or a custom permission gate to enforce record-creation approval. Monitor for anomalous bulk creation activity via Event Monitoring API Usage events. Remove CanCreate from profiles where no create workflow exists."
        ),
        "OPSEC": (
            "Record creation populates the CreatedById and CreatedDate standard fields on the new record but generates no Setup Audit Trail entry. Bulk record creation via the Bulk API is visible in API Usage event logs with Event Monitoring, but individual record creation is invisible in standard logs. Apex triggers attached to the object execute in the creator's context upon creation and can be abused as side-channels."
        ),
    },

    # Source: Salesforce Help "Object Permissions" - Edit permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Grants the ability to modify existing records of this object type,
    # subject to sharing rules. Requires Read.
    "CanEdit": {
        "General": (
            "Grants the ability to edit existing records of this object type that are accessible "
            "to the user (per sharing rules). Requires Read permission on the object. "
            "Does not allow editing records outside the user's sharing access."
        ),
        "AbuseInfo": (
            "Enables data tampering on any record the user can access. For critical objects such as "
            "User (changing email/phone for MFA bypass), Contract, or custom security tables, "
            "Edit access is a direct data-integrity risk. When sharing is broad, effective scope "
            "extends to all records in the org."
        ),
        "References": (
            "MITRE ATT&CK: T1565 - Data Manipulation / T1098 - Account Manipulation | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Restrict CanEdit on sensitive objects to users with a clear business justification. Enable Field History Tracking on critical fields for important objects. Audit profile and permission set changes that grant CanEdit on sensitive objects via Setup Audit Trail. For compliance-sensitive records, implement record-locking mechanisms to prevent modification after a defined workflow stage."
        ),
        "OPSEC": (
            "Individual record edits are not logged in Setup Audit Trail; only the standard LastModifiedBy and SystemModstamp fields update on the record. Field History Tracking (if configured per-object) logs field-level changes but does not capture all fields by default. Large-scale edits via the Bulk API Update operation are visible in Event Monitoring API usage logs but individual record edits are forensically silent."
        ),
    },

    # Source: Salesforce Help "Object Permissions" - Delete permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Grants the ability to delete records of this object type that the user
    # can access. Deleted records go to the Recycle Bin (15 days).
    "CanDelete": {
        "General": (
            "Grants the ability to delete records of this object type that the user can access. "
            "Deleted records are moved to the Recycle Bin for 15 days before permanent removal. "
            "Requires both Read and Edit permissions."
        ),
        "AbuseInfo": (
            "Enables targeted or bulk data destruction. Even with Recycle Bin recovery, mass deletion "
            "causes service disruption and data-integrity incidents. For objects used in financial or "
            "compliance workflows, deletion can undermine audit trails. Combined with CanModifyAll, "
            "a holder can delete any record org-wide bypassing ownership constraints."
        ),
        "References": (
            "MITRE ATT&CK: T1485 - Data Destruction / T1070 - Indicator Removal | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Apply CanDelete conservatively; require explicit justification for delete permissions on sensitive or compliance-relevant objects. Set up automation to alert on bulk deletions (e.g., via Platform Events or Flows monitoring RecordDeleted triggers). For financial and audit objects, prefer a soft-delete pattern using a custom IsArchived field rather than hard deletes. Review holders quarterly."
        ),
        "OPSEC": (
            "Record deletions move records to the Recycle Bin and update the LastModifiedBy and SystemModstamp fields on the Recycle Bin item. There is no Setup Audit Trail entry for data deletions. Event Monitoring Bulk API Delete events can detect bulk deletions but individual record deletes are invisible in standard logs. Recycle Bin items are recoverable for 15 days and then permanently removed unless restored."
        ),
    },

    # Source: Salesforce Help "Object Permissions" - View All Records permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Grants access to ALL records of this object type, completely bypassing
    # sharing rules, role hierarchy, and OWD settings.
    "CanViewAll": {
        "General": (
            "Grants read access to ALL records of this object type, regardless of record ownership, "
            "sharing rules, role hierarchy, or Organisation-Wide Default (OWD) settings. "
            "Equivalent to a per-object ViewAllData for this specific SObject."
        ),
        "AbuseInfo": (
            "Complete sharing bypass for this object. Even in a Private OWD org, the holder can read "
            "every record. For sensitive objects this enables full dataset exfiltration without needing "
            "ModifyAllData. Particularly dangerous on User, custom credential/secret, or financial objects "
            "where private sharing is the primary access control."
        ),
        "References": (
            "MITRE ATT&CK: T1530 - Data from Cloud Storage / T1213 - Data from Information Repositories | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Treat CanViewAll as equivalent to a per-object ViewAllData. Restrict to integration and service accounts with a documented operational need; remove from all human user profiles. Track any profile or permission set modification that adds this flag via Setup Audit Trail monitoring. Conduct quarterly access reviews with designated data owners for each sensitive object."
        ),
        "OPSEC": (
            "CanViewAll does not generate per-record read events in standard logs. Bulk data extraction using this permission is indistinguishable from normal administrative activity in default logging. Event Monitoring Data Export and Report event types (additional licence required) may capture large-scale reads. Field-level visibility remains constrained by FLS settings regardless of CanViewAll."
        ),
    },

    # Source: Salesforce Help "Object Permissions" - Modify All Records permission
    # https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm
    # Grants read, edit, delete, transfer, and approve access to ALL records
    # of this object type, completely bypassing sharing and ownership controls.
    "CanModifyAll": {
        "General": (
            "Grants read, edit, delete, transfer ownership, and approval override on ALL records "
            "of this object type, regardless of record ownership, sharing rules, or OWD settings. "
            "Equivalent to a per-object ModifyAllData for this specific SObject."
        ),
        "AbuseInfo": (
            "Complete sharing and ownership bypass for this object. A holder can read, alter, or destroy "
            "every record without restriction. On the User object this allows mass account manipulation "
            "(e.g. resetting all email addresses). On custom sensitive objects it enables full exfiltration "
            "and destruction. Treat as Tier Zero for any object containing credentials, PII, or financial data."
        ),
        "References": (
            "MITRE ATT&CK: T1565 - Data Manipulation / T1485 - Data Destruction | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userperms.htm"
        ),
        "RemediationInfo": (
            "Treat CanModifyAll as Tier Zero for any sensitive object. Restrict to break-glass integration accounts only and document all exceptions with a named business owner. Remove from all human user profiles and non-critical permission sets. Regularly audit CanModifyAll grants on the User, Contact, Account, and any custom PII, financial, or credential-store objects."
        ),
        "OPSEC": (
            "CanModifyAll-based edits appear in the record's LastModifiedBy and SystemModstamp fields but not in Setup Audit Trail. Bulk operations via the Bulk API are visible in API Usage event logs with Event Monitoring. Ownership transfer and approval override operations enabled by this permission leave no distinct audit trail entry beyond the record modification itself, making attribution during IR challenging."
        ),
    },
}


# -------------------------
# Assignment Edge Context
# -------------------------
# Contextual descriptions and impact statements for structural assignment edges.
# These properties are added to edges that attach users to permission principals
# (Profiles, PermissionSets, PermissionSetGroups) so auditors can understand the
# significance of each relationship type directly in the BloodHound GUI.
#
# Sources:
#   - Salesforce Help: "Permission Sets and Permission Set Groups"
#     https://help.salesforce.com/s/articleView?id=sf.perm_sets_overview.htm
#   - Salesforce Help: "Profiles Overview"
#     https://help.salesforce.com/s/articleView?id=sf.admin_userprofiles.htm
#   - Salesforce Help: "Permission Set Groups"
#     https://help.salesforce.com/s/articleView?id=sf.perm_set_groups.htm
#   - Salesforce Security Guide: "User Authentication and Profiles"
#     https://help.salesforce.com/s/articleView?id=sf.permissions_about_perms_and_accts.htm
#
# Property keys are PascalCase per OpenGraph schema requirements.
# To update or extend descriptions, add/modify entries below and re-run the collector.

ASSIGNMENT_EDGE_CONTEXT: Dict[str, Dict[str, str]] = {
    # Source: Salesforce Help "Profiles Overview"
    # https://help.salesforce.com/s/articleView?id=sf.admin_userprofiles.htm
    # Every Salesforce user is assigned exactly one Profile. The Profile defines
    # the user's baseline permissions: object access, system permissions, page
    # layouts, record types, field-level security, login hours, and IP restrictions.
    "AssignedProfile": {
        "General": (
            "Every Salesforce user is assigned exactly one Profile, which defines their baseline "
            "access: object-level CRUD permissions, system permissions, field-level security, "
            "page layouts, record types, login hours, and IP login restrictions. "
            "The Profile is the primary permission boundary for the user."
        ),
        "AbuseInfo": (
            "The Profile is the root of a user's permission chain. Compromise of a high-privilege "
            "Profile (e.g. System Administrator) grants all permissions of that Profile to the user. "
            "Reassigning a user to a more permissive Profile is a direct privilege escalation path "
            "and requires only ManageUsers or ManageProfilesPermissionsets to execute silently."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1548 - Abuse Elevation Control Mechanism | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userprofiles.htm"
        ),
        "RemediationInfo": (
            "Enforce a formal profile review for each distinct profile in the org. Minimise the total number of profiles; prefer permission sets for additive access grants. Require documented approval before assigning users to elevated profiles such as System Administrator. Monitor Setup Audit Trail for profile assignment changes on privileged accounts and review profile-to-user mappings quarterly."
        ),
        "OPSEC": (
            "Profile reassignment is logged in Setup Audit Trail as a UserManagement event (ProfileId field change on the User record). The new profile takes effect immediately. There is no per-user notification sent to the affected user when their profile changes. Assigning a user to the System Administrator profile is a high-visibility event in Setup Audit Trail monitoring, but assignment to a custom high-privilege profile may not trigger default security alerts."
        ),
    },

    # Source: Salesforce Help "Permission Sets and Permission Set Groups"
    # https://help.salesforce.com/s/articleView?id=sf.perm_sets_overview.htm
    # A Permission Set is an additive set of permissions assigned directly to a
    # user on top of their Profile. A user can hold multiple Permission Sets.
    # They grant object, field, system, and app permissions additionally.
    "AssignedPermissionSet": {
        "General": (
            "A Permission Set grants additional permissions on top of a user's Profile. "
            "Users can hold multiple Permission Sets simultaneously. They can grant "
            "object-level CRUD, field-level security, system permissions, and connected app "
            "authorization access beyond what the Profile allows."
        ),
        "AbuseInfo": (
            "Permission Sets are the primary vector for incremental privilege escalation in Salesforce. "
            "An attacker with ManageProfilesPermissionsets can create or edit a Permission Set to add "
            "high-risk permissions (e.g. ModifyAllData, AuthorApex) and silently assign it to any user. "
            "Because each assignment is additive, the effective permission set of a user is the union "
            "of all their assigned Permission Sets plus their Profile."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1548 - Abuse Elevation Control Mechanism | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.perm_sets_overview.htm"
        ),
        "RemediationInfo": (
            "Implement an approval workflow for permission set assignments on high-risk permission sets. Enumerate all assignments quarterly via SOQL: SELECT AssigneeId, PermissionSet.Name FROM PermissionSetAssignment. Remove unused or expired assignments. For temporary elevated access, use time-limited permission sets with automated expiry rather than persistent assignments."
        ),
        "OPSEC": (
            "Permission set assignments are logged in Setup Audit Trail under the PermissionSetAssignment event type. The assignment takes effect immediately without any notification to the affected user. Assigning a high-risk permission set with an innocuous name is unlikely to trigger alerting unless the assignment event itself is actively monitored. Assignment audit covers only the assignment event, not subsequent use of the granted permissions."
        ),
    },

    # Source: Salesforce Help "Permission Set Groups"
    # https://help.salesforce.com/s/articleView?id=sf.perm_set_groups.htm
    # A Permission Set Group bundles multiple Permission Sets into a single
    # assignable unit. When assigned to a user, the user receives all permissions
    # from all member Permission Sets simultaneously.
    "AssignedPermissionSetGroup": {
        "General": (
            "A Permission Set Group bundles multiple Permission Sets into a single assignable unit. "
            "When a user is assigned a Permission Set Group, they receive the combined permissions "
            "of all member Permission Sets at once. Simplifies bulk permission management."
        ),
        "AbuseInfo": (
            "Assigning a Permission Set Group can silently grant a large set of permissions in a single "
            "operation, making the blast radius harder to audit than individual Permission Set assignments. "
            "A malicious admin can embed high-risk Permission Sets (e.g. one containing ModifyAllData) "
            "inside a Group with an innocuous name, then assign the Group to a target user."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1548 - Abuse Elevation Control Mechanism | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.perm_set_groups.htm"
        ),
        "RemediationInfo": (
            "Audit all permission set group assignments quarterly; enumerate the effective permissions of each group to ensure no unintended Tier Zero permissions are bundled. Require change management approval before adding Permission Sets containing high-risk permissions to any group. Remove unused group assignments and maintain documentation of each group's intended access scope."
        ),
        "OPSEC": (
            "Permission Set Group assignments are logged in Setup Audit Trail. The full blast radius of a single group assignment can be large if the group bundles multiple permission sets; auditors must enumerate all component Permission Sets via PermissionSetGroupComponent to assess the true effective risk. There is no per-user notification on group assignment. A group with an innocuous name containing a high-risk permission set is a low-detection escalation path."
        ),
    },

    # Source: Salesforce Help "Permission Set Groups" - component membership
    # https://help.salesforce.com/s/articleView?id=sf.perm_set_groups.htm
    # PermissionSetGroupComponent records define which Permission Sets are bundled
    # inside a Permission Set Group. This edge represents that containment.
    "IncludesPermissionSet": {
        "General": (
            "Indicates that this Permission Set is a member of the Permission Set Group. "
            "Users assigned the Group automatically receive all permissions from this "
            "member Permission Set, in addition to all other member sets in the Group."
        ),
        "AbuseInfo": (
            "Containment within a Group is a key step in the transitive permission chain. "
            "Auditing a Group assignment requires inspecting all IncludesPermissionSet edges "
            "to understand the full effective permission scope. A single high-risk Permission Set "
            "embedded in an otherwise benign Group elevates every user holding that Group assignment."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.perm_set_groups.htm"
        ),
        "RemediationInfo": (
            "Regularly audit the composition of each Permission Set Group; remove high-risk Permission Sets from groups assigned to broad user populations. Document each group's intended scope and required component permission sets. Require change approval before adding any Permission Set to an existing group, since the change immediately propagates to all users holding that group assignment."
        ),
        "OPSEC": (
            "Changes to PermissionSetGroupComponent (adding or removing a Permission Set from a group) are logged in Setup Audit Trail. The change propagates to all users holding the group assignment without generating per-user log entries or notifications. A single group composition change can silently escalate a large number of users, making this one of the highest-leverage low-visibility modification paths in the Salesforce permission model."
        ),
    },

    # Source: Salesforce Help "Profiles Overview" - Profile-owned PermissionSet
    # https://help.salesforce.com/s/articleView?id=sf.admin_userprofiles.htm
    # Salesforce internally represents every Profile as a PermissionSet record
    # (IsOwnedByProfile=true). This edge links the Profile node to its backing
    # PermissionSet, enabling permission queries through a unified interface.
    "HasPermissionSet": {
        "General": (
            "Links a Profile to its internal PermissionSet representation "
            "(IsOwnedByProfile=true). Salesforce models Profiles as a specialised "
            "PermissionSet internally, allowing object, field, and system permissions "
            "to be queried uniformly across Profiles and standalone PermissionSets."
        ),
        "AbuseInfo": (
            "This structural edge is required to traverse the full permission chain from a Profile "
            "to its underlying permissions. Attackers who can modify the backing PermissionSet of a "
            "Profile (via ManageProfilesPermissionsets) can elevate all users on that Profile "
            "simultaneously, affecting every user assigned to it rather than a single individual."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1548 - Abuse Elevation Control Mechanism | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_userprofiles.htm"
        ),
        "RemediationInfo": (
            "This is a read-only structural relationship; changes cannot be made here directly. Remediation is implemented at the Profile level: review each Profile's embedded permission set for dangerous system permissions via SOQL on the PermissionSet object (WHERE IsOwnedByProfile = true). Reduce the number of profiles with Tier Zero system permissions and prefer permission set delegation for elevated access."
        ),
        "OPSEC": (
            "This edge represents an internal Salesforce data model link and cannot be created or deleted independently of profile management. It is not logged in Setup Audit Trail as a separate event; changes appear as profile-level permission modifications. There is no distinct evasion opportunity here; monitoring should focus on profile permission changes which are the underlying actionable audit trail events."
        ),
    },

    # Source: Salesforce Help "Role Hierarchies" - user role assignment
    # https://help.salesforce.com/s/articleView?id=sf.admin_roles.htm
    # Every Salesforce user can be assigned to exactly one UserRole. The role
    # determines record visibility: users in parent roles can see records owned
    # by users in all subordinate roles below them in the hierarchy.
    "HasRole": {
        "General": (
            "Assigns a user to a role in the Salesforce role hierarchy. A user's role determines "
            "which records they can see: users in parent roles automatically gain read access to "
            "records owned by users in all subordinate (child) roles beneath them. "
            "Only one role can be assigned per user."
        ),
        "AbuseInfo": (
            "Role assignment is a record-visibility escalation path. Placing a user into a higher "
            "role (e.g. CEO, VP Sales) grants implicit read access to every record owned by every "
            "subordinate user in the hierarchy, bypassing individual sharing rules. "
            "An attacker with ManageRoles or ManageUsers can silently re-assign a user to a more "
            "privileged role, expanding their data access without modifying profiles or permission sets."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1548 - Abuse Elevation Control Mechanism | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_roles.htm"
        ),
        "RemediationInfo": (
            "Require an approval workflow for role assignments, particularly to senior roles such as VP, CEO, or Global Admin. Audit all user role assignments quarterly and compare against the current organisational chart. Remove role assignments from service and integration accounts where record-visibility expansion via the role hierarchy is unintended."
        ),
        "OPSEC": (
            "User role assignment changes appear in Setup Audit Trail as UserManagement events (UserRoleId field change on the User record). The change takes effect immediately and silently expands or contracts the user's record visibility. There is no per-user notification to the affected user or to users in parent roles who gain new record visibility as a consequence of the reassignment."
        ),
    },

    # Source: Salesforce Help "Role Hierarchies" - ParentRoleId field on UserRole
    # https://help.salesforce.com/s/articleView?id=sf.admin_roles.htm
    # The ParentRoleId field on a UserRole record establishes the upward hierarchy.
    # Users in parent roles inherit visibility over records owned by child-role users.
    # This creates a transitive privilege escalation path up the org chart.
    "InheritsRole": {
        "General": (
            "Represents the parent-child relationship between two roles in the Salesforce role "
            "hierarchy. A child role's users have their records visible to users in the parent role. "
            "The relationship is transitive: data propagates up through every ancestor role."
        ),
        "AbuseInfo": (
            "Defines a transitive data-access path up the org chart. An attacker who controls a "
            "user in a parent role can read all records owned by every user in every subordinate role. "
            "Manipulating the hierarchy (via ManageRoles) to insert a controlled node above high-value "
            "roles converts an unprivileged account into an org-wide read socket without any "
            "permission-set changes, making detection harder."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1548 - Abuse Elevation Control Mechanism | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_roles.htm"
        ),
        "RemediationInfo": (
            "Review the role hierarchy annually for excessive depth, overly broad parent roles, or roles that remain from former employees. Remove unused or deprecated roles. Ensure the hierarchy accurately reflects the current organisational structure. Document each role's intended data-visibility scope and flag any role whose parent access is disproportionate to its stated purpose."
        ),
        "OPSEC": (
            "Role hierarchy changes (modifying ParentRoleId on a UserRole record) are logged in Setup Audit Trail. The change affects data visibility for all users in the modified role and all its descendants transitively, but only the role record change is logged — not the resultant access changes for affected users. Detection of hierarchy manipulation requires comparing hierarchy snapshots over time rather than relying on reactive alerting."
        ),
    },
}

# Context for group membership, queue ownership, connected app, OAuth authorization,
# and field-level security edges.
GROUP_AND_ACCESS_EDGE_CONTEXT: Dict[str, Dict[str, str]] = {

    # Source: Salesforce Help "Create and Manage Groups"
    # https://help.salesforce.com/s/articleView?id=sf.admin_groups.htm
    # A GroupMember record links a User or Group (UserOrGroupId) to a Public Group or
    # Queue (GroupId). Group membership drives record sharing via sharing rules and
    # manual shares. Nested groups propagate access transitively through the hierarchy.
    "MemberOfGroup": {
        "General": (
            "Records that a user or nested group is a member of a Salesforce Public Group or Queue. "
            "Membership drives record sharing: any sharing rule that grants a group access to records "
            "applies to every direct and indirect member. Nested group membership propagates "
            "transitively, so a user in a sub-group inherits all access granted to ancestor groups."
        ),
        "AbuseInfo": (
            "Adding a user to a group silently expands their record access without changing profiles "
            "or permission sets. An attacker with ManageUsers can insert a controlled account into a "
            "privileged group to inherit all sharing-rule-granted access for that group. Nested groups "
            "(group-in-group) compound this: a single membership can cascade access across multiple "
            "sharing rules simultaneously, making the escalation difficult to detect."
        ),
        "References": (
            "MITRE ATT&CK: T1098 - Account Manipulation / T1069 - Permission Groups Discovery | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_groups.htm"
        ),
        "RemediationInfo": (
            "Audit all Public Group memberships quarterly, focusing on groups referenced in sharing rules. Remove users from groups that grant record access beyond their job function. Restrict who can manage group membership (requires ManageUsers or delegated group management). Document the purpose and intended access scope of every sharing group."
        ),
        "OPSEC": (
            "Group membership changes are logged in Setup Audit Trail as GroupMember additions or removals. The access change takes effect immediately upon membership addition. Nested group memberships (group-in-group) create transitive access that is not directly visible without traversing the full group tree. No notification is sent to the user when they are added to or removed from a group."
        ),
    },

    # Source: Salesforce Help "Create and Manage Groups"
    # https://help.salesforce.com/s/articleView?id=sf.admin_groups.htm
    # HasMember is the inverse of MemberOfGroup: it represents the Group -> Member
    # direction, mirroring the same GroupMember record for UI traversal (e.g., listing
    # all members of a given group in BloodHound graph queries).
    "HasMember": {
        "General": (
            "Represents a Public Group or Queue containing a user or nested group as a member. "
            "This is the inverse direction of MemberOfGroup and mirrors the same GroupMember record "
            "from the Group's perspective, enabling graph traversal from group outward to its members."
        ),
        "AbuseInfo": (
            "Querying inbound HasMember edges on a high-privilege group reveals every identity that "
            "inherits its sharing access. An attacker enumerating group membership can identify "
            "over-provisioned groups and target weaker member accounts to gain equivalent access. "
            "Groups containing other groups (nested) create a fan-out risk where a single insertion "
            "gives access to all records shared with the parent group."
        ),
        "References": (
            "MITRE ATT&CK: T1069 - Permission Groups Discovery / T1098 - Account Manipulation | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_groups.htm"
        ),
        "RemediationInfo": (
            "Audit the membership roster of all security-relevant groups, particularly those referenced in record sharing rules. Review groups with the broadest sharing impact first. Restrict group administration to a dedicated operations team and require a documented justification for membership changes."
        ),
        "OPSEC": (
            "This is the inverse direction of the MemberOfGroup edge, representing the same GroupMember record viewed from the Group's perspective. Monitoring recommendations are identical to MemberOfGroup: Setup Audit Trail records all group membership changes. Enumerating group membership via direct SOQL queries leaves no audit trail entry, enabling silent reconnaissance of group scope."
        ),
    },

    # Source: Salesforce Help "Queues Overview"
    # https://help.salesforce.com/s/articleView?id=sf.queues_overview.htm
    # A QueueSobject record defines which SObject types a Queue can own. When a record
    # is assigned to a Queue, all Queue members can read and update it. This is a form
    # of implicit sharing that bypasses standard org-wide defaults for affected objects.
    "CanOwnObject": {
        "General": (
            "Indicates that a Queue is configured to own records of a specific SObject type. "
            "When a record of that type is assigned to the Queue, every Queue member automatically "
            "gains read and edit access to it. This implicit sharing applies regardless of org-wide "
            "defaults and individual user permissions for the object."
        ),
        "AbuseInfo": (
            "Queue ownership bypasses standard sharing rules: any user added to the Queue can read "
            "and modify all records assigned to it, even if the org-wide default is Private. An "
            "attacker who can add users to a Queue (via ManageUsers or group administration) gains "
            "access to every record owned by that Queue. High-value queues (e.g., those owning "
            "Cases or Leads with sensitive PII) are attractive escalation targets."
        ),
        "References": (
            "MITRE ATT&CK: T1078 - Valid Accounts / T1098 - Account Manipulation | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.queues_overview.htm"
        ),
        "RemediationInfo": (
            "Restrict Queue object type configurations to queues managed by accountable teams. Apply additional sharing controls when a Queue owns records of sensitive object types. Periodically review QueueSobject records to remove unused queue-to-object associations. Limit who can manage Queue membership to prevent unauthorised record access via Queue ownership."
        ),
        "OPSEC": (
            "QueueSobject record creation and deletion are logged in Setup Audit Trail. Once the Queue-object association exists, records can be assigned to the Queue without further audit trail entries beyond the record's OwnerId field change. Queue membership changes (adding a user to a Queue) are logged as GroupMember events in Setup Audit Trail. The queue-record assignment itself is not a Setup Audit Trail event."
        ),
    },

    # Source: Salesforce Help "Understanding Sharing" and "User Role Hierarchy"
    # https://help.salesforce.com/s/articleView?id=sf.security_sharing.htm
    # https://help.salesforce.com/s/articleView?id=sf.security_roles_overview.htm
    # An OwnerId field on a record identifies the user responsible for that record.
    # When an object's OWD is Private or Public Read Only, the role hierarchy grants
    # managers implicit read (and sometimes edit) access to records owned by subordinates.
    "OwnsRecordsOfObject": {
        "General": (
            "Indicates that a Salesforce user owns at least one record of the specified SObject type. "
            "Record ownership is significant when the org-wide default (OWD) for the object is Private "
            "or Public Read Only: roles above the owning user in the role hierarchy can view (and in "
            "some cases edit) those records via implicit role-based sharing. This edge enables "
            "BloodHound path traversal to surface indirect data access that flows upward through the "
            "role hierarchy from record owners to their managers."
        ),
        "AbuseInfo": (
            "When an object's OWD is Private, a user above the owner in the role hierarchy automatically "
            "gains read access to all records owned by subordinates. An attacker who compromises any "
            "manager account inherits read (and potentially write) access to every record owned by "
            "users below them. Combined with InheritsRole edges, this models the full attack surface "
            "for privilege escalation through record ownership. If a sensitive object has even one "
            "record owned by a low-privileged user, a manager above that user in the hierarchy gains "
            "implicit read access without any explicit permission assignment."
        ),
        "References": (
            "MITRE ATT&CK: T1530 - Data from Cloud Storage | "
            "Salesforce Help - Sharing Model: https://help.salesforce.com/s/articleView?id=sf.security_sharing.htm | "
            "Salesforce Help - Role Hierarchy: https://help.salesforce.com/s/articleView?id=sf.security_roles_overview.htm"
        ),
        "RemediationInfo": (
            "Audit who owns records of sensitive custom objects and compare against the role hierarchy. "
            "If a sensitive object uses a Private OWD, ensure all record owners are at the lowest appropriate "
            "level in the role hierarchy to minimise implicit read access propagation upward. Consider "
            "using Apex sharing or manual sharing rules to grant access explicitly rather than relying on "
            "role-hierarchy inheritance. Review and remove unnecessary records owned by high-role users "
            "who should not be creating data at that level."
        ),
        "OPSEC": (
            "Record access via role hierarchy inheritance is not individually logged per record read — "
            "it is implicit sharing enforced at query time. Standard audit logs do not record when a "
            "manager reads a subordinate's owned records via role-based sharing. Event Monitoring (if "
            "licensed) captures API query events but does not attribute them to role-hierarchy sharing "
            "specifically. Changing record ownership (OwnerId update) is visible in the record's field "
            "history if field history tracking is enabled on OwnerId, and in Event Monitoring as a "
            "field update event."
        ),
    },

    # Source: Salesforce Help "Connected Apps Overview"
    # https://help.salesforce.com/s/articleView?id=sf.connected_app_overview.htm
    # ConnectedApp.CreatedById records the admin who registered the OAuth application
    # in the org. This is important for auditing app provenance and identifying apps
    # created under compromised or over-privileged admin accounts.
    "CreatedBy": {
        "General": (
            "Links a Connected App to the Salesforce user who created it. This edge captures the "
            "administrative provenance of an OAuth application, recording which admin registered "
            "the app and when. It enables timeline analysis of app creation events and ties each "
            "app to its originating account for audit purposes."
        ),
        "AbuseInfo": (
            "A Connected App created by a compromised admin may have been configured with overly "
            "broad OAuth scopes or relaxed IP restrictions intentionally. Tracing CreatedBy edges "
            "allows investigators to correlate suspicious app creation with known account compromise "
            "windows. Attackers with admin access (ModifyAllData, CustomizeApplication) can register "
            "rogue OAuth apps to establish persistent API access that survives password resets."
        ),
        "References": (
            "MITRE ATT&CK: T1098.001 - Account Manipulation: Additional Cloud Credentials | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.connected_app_overview.htm"
        ),
        "RemediationInfo": (
            "Audit all connected apps, with particular attention to those created by accounts that are no longer active or that were potentially compromised. Treat orphaned apps (where the creator account has been deleted or deactivated) as suspect and investigate their configuration. Implement a connected app governance process requiring security review before any new app is registered in production."
        ),
        "OPSEC": (
            "Connected App creation is logged in Setup Audit Trail. Once created, the app persists even if the creator's account is deactivated or deleted. OAuth tokens already issued by the app continue to function until explicitly revoked, meaning a rogue app created under a compromised admin account remains a valid persistence mechanism even after the admin account is remediated."
        ),
    },

    # Source: Salesforce Help "Manage Connected App Access in Your Organization"
    # https://help.salesforce.com/s/articleView?id=sf.connected_app_manage.htm
    # SetupEntityAccess records grant a Profile or PermissionSet the ability to authorize
    # (OAuth-login to) a specific ConnectedApplication. Without this access, users on the
    # profile cannot complete the OAuth flow for the app, regardless of app-level policies.
    "CanAuthorize": {
        "General": (
            "Grants a Profile or PermissionSet the right to authorize (OAuth-authenticate to) a "
            "specific Connected App. Users assigned to a Profile or PermissionSet with this access "
            "can initiate and complete the OAuth authorization flow for the app, obtaining tokens "
            "scoped to whatever permissions the app requests."
        ),
        "AbuseInfo": (
            "CanAuthorize edges identify which user populations can obtain OAuth tokens for each "
            "Connected App. Apps with Full Access (full) or API-only scopes represent high-value "
            "targets: an attacker who compromises any user in an authorized Profile gains API-level "
            "org access via the app's token. Broad profiles (e.g., System Administrator) with "
            "CanAuthorize edges to powerful apps are critical attack-path nodes."
        ),
        "References": (
            "MITRE ATT&CK: T1550.001 - Use Alternate Authentication Material: Application Access Token | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.connected_app_manage.htm"
        ),
        "RemediationInfo": (
            "Apply least-privilege to SetupEntityAccess — only profiles and permission sets with a documented business need should be able to authorise each Connected App. Remove CanAuthorize access from broad profiles (e.g., Standard User) for apps with Full Access (full) or API-only OAuth scopes. Audit connected app authorisation policies annually and revoke orphaned access grants."
        ),
        "OPSEC": (
            "SetupEntityAccess changes are logged in Setup Audit Trail. Individual OAuth authorisation flows appear in LoginHistory as OAuthToken login events, providing visibility at the point of token issuance. Token refresh events are not separately logged in standard audit. Tokens obtained via CanAuthorize remain valid until the session timeout or explicit revocation, even if the CanAuthorize permission is subsequently removed from the profile or permission set."
        ),
    },

    # Source: Salesforce Help "Field-Level Security"
    # https://help.salesforce.com/s/articleView?id=sf.admin_fls.htm
    # FieldPermissions.PermissionsEdit=true means the field is both visible and editable.
    # The IsVisible edge type captures full read+write field access granted through a
    # Profile or PermissionSet. FLS is evaluated in addition to (not instead of) CRUD:
    # a user needs both object-level CanRead/CanEdit AND field-level IsVisible to read/write a field.
    "IsVisible": {
        "General": (
            "Grants a Profile or PermissionSet read and write access to a specific field on an "
            "SObject (FieldPermissions.PermissionsEdit=true). Users with this edge can both see "
            "the field value and modify it, subject to object-level CRUD permissions also being "
            "present. Field-level security is evaluated independently of and in addition to "
            "object-level permissions."
        ),
        "AbuseInfo": (
            "IsVisible edges on sensitive fields (e.g., SSN__c, SalaryData__c, BankAccount__c, "
            "custom PII fields) directly expose confidential data. If a Profile or PermissionSet has "
            "IsVisible on a high-value field, every user on that Profile can read and overwrite that "
            "field. Overly broad FLS is one of the most common data-exposure findings in Salesforce "
            "orgs. An attacker with ManageProfilesPermissionsets can add IsVisible access to harvest "
            "sensitive fields across the entire user base."
        ),
        "References": (
            "MITRE ATT&CK: T1552 - Unsecured Credentials / T1213 - Data from Information Repositories | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_fls.htm"
        ),
        "RemediationInfo": (
            "Configure Field-Level Security in alignment with data classification policy; restrict IsVisible (edit) access on sensitive fields — such as PII, salary, financial, and credential fields — to named permission sets only. Audit FLS configuration via the Field Accessibility tool or SOQL on FieldPermissions. Remove IsVisible from standard and broadly-assigned profiles for all classified fields."
        ),
        "OPSEC": (
            "FLS permission changes are logged in Setup Audit Trail as profile or permission set metadata updates. Actual field reads and writes (exercising IsVisible access) are not logged in standard audit. Event Monitoring with Field Audit Trail (additional licence required) is needed to capture field-level access events. UI page-layout field hiding does not restrict API access — FLS is the only platform-enforced control and must be relied upon as the definitive access boundary."
        ),
    },

    # Source: Salesforce Help "Field-Level Security"
    # https://help.salesforce.com/s/articleView?id=sf.admin_fls.htm
    # FieldPermissions where PermissionsEdit=false but PermissionsRead=true creates a
    # read-only field access grant. The ReadOnly edge captures this constrained FLS:
    # the user can see the field value but cannot modify it.
    "ReadOnly": {
        "General": (
            "Grants a Profile or PermissionSet read-only access to a specific field on an SObject "
            "(FieldPermissions.PermissionsRead=true, PermissionsEdit=false). Users with this edge "
            "can view the field value but cannot modify it, subject to object-level read access also "
            "being present. ReadOnly FLS is commonly used for audit fields, computed values, and "
            "sensitive fields that must be visible but protected from modification."
        ),
        "AbuseInfo": (
            "ReadOnly edges on sensitive fields still expose confidential data to every user on the "
            "relevant Profile or PermissionSet. Read-only access to fields like SSN, salary, or "
            "financial data is sufficient for data exfiltration even without edit capability. "
            "Overly permissive ReadOnly FLS is a frequent finding in orgs that rely on UI restrictions "
            "rather than true field-level security, since API access (via tools or connected apps) "
            "bypasses page-layout field hiding and only respects FLS."
        ),
        "References": (
            "MITRE ATT&CK: T1552 - Unsecured Credentials / T1213 - Data from Information Repositories | "
            "Salesforce Help: https://help.salesforce.com/s/articleView?id=sf.admin_fls.htm"
        ),
        "RemediationInfo": (
            "Treat ReadOnly FLS on sensitive fields as a data-exposure risk equivalent to full read access and apply the same access restrictions. Audit FieldPermissions records for classified fields quarterly. Prefer explicit denial (no permission configured) over ReadOnly grants for fields containing PII, financial data, or credentials on standard user profiles."
        ),
        "OPSEC": (
            "FLS ReadOnly permission changes are logged in Setup Audit Trail as profile or permission set metadata updates. Field reads exercising ReadOnly FLS leave no per-record access log in standard audit. API access via tools such as Salesforce Inspector, Workbench, or custom integrations bypasses all page-layout restrictions and respects only FLS, meaning ReadOnly-protected sensitive fields are fully readable to any user with API access and this grant."
        ),
    },
}


# -------------------------
# Edge model
# -------------------------

class Edge:
    """Backward-compatible shim — callers outside this module should migrate to
    _make_edge().  Only EdgeBuilder methods inside this file use it."""
    def __init__(self, start, end, kind, properties=None):
        self._bh = _make_edge(start, end, kind, properties)
    def to_dict(self):
        return self._bh.to_dict()


# -------------------------
# Edge builder
# -------------------------

class EdgeBuilder:

    # -------------------------
    # Direct Assignments
    # -------------------------

    def build_profile_assignments(self, users: Dict[str, Any]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        # Source: ASSIGNMENT_EDGE_CONTEXT dict defined in this module
        ctx = ASSIGNMENT_EDGE_CONTEXT.get(EdgeKinds.ASSIGNED_PROFILE)
        for u in users.get("records", []):
            profile_id = u.get("ProfileId")
            if profile_id:
                edges.append(_make_edge(u["Id"], profile_id, EdgeKinds.ASSIGNED_PROFILE, dict(ctx) if ctx else None))
        return edges

    def build_permission_set_assignments(
        self,
        assignments: Dict[str, Any],
        permission_sets: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Build *direct* PermissionSetAssignment edges.

        IMPORTANT:
        Salesforce exposes the Profile "permission set" (IsOwnedByProfile=true)
        through PermissionSetAssignment as well. Those should NOT be modeled as
        AssignedPermissionSet from User -> PermissionSet, because the user
        inherits them via AssignedProfile -> Profile.

        So:
        - Skip PermissionSetIds that are profile-owned
        """
        edges: List[Dict[str, Any]] = []

        profile_owned_permset_ids: Set[str] = set()
        if permission_sets:
            for ps in permission_sets.get("records", []):
                if ps.get("IsOwnedByProfile") is True and ps.get("Id"):
                    profile_owned_permset_ids.add(ps["Id"])

        for a in assignments.get("records", []):
            assignee = a.get("AssigneeId")
            permset = a.get("PermissionSetId")

            if not assignee or not permset:
                continue

            if permset in profile_owned_permset_ids:
                # This is the Profile's "permission set" representation.
                # Don’t draw User -> PermissionSet as direct assignment.
                continue

            # Source: ASSIGNMENT_EDGE_CONTEXT dict defined in this module
            ctx = ASSIGNMENT_EDGE_CONTEXT.get(EdgeKinds.ASSIGNED_PERMISSION_SET)
            edges.append(_make_edge(assignee, permset, EdgeKinds.ASSIGNED_PERMISSION_SET, dict(ctx) if ctx else None))

        return edges

    def build_permission_set_group_assignments(
        self,
        psg_assignments: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        User -> PermissionSetGroup
        sourced from PermissionSetAssignment.PermissionSetGroupId
        """
        edges: List[Dict[str, Any]] = []

        for a in psg_assignments.get("records", []):
            user_id = a.get("AssigneeId")
            psg_id = a.get("PermissionSetGroupId")
            if not user_id or not psg_id:
                continue

            props = {}
            if a.get("Id"):
                props["PermissionSetAssignmentId"] = a["Id"]
            sm = a.get("SystemModstamp") or a.get("SystemModStamp")
            if sm:
                props["SystemModstamp"] = sm

            # Source: ASSIGNMENT_EDGE_CONTEXT dict defined in this module
            ctx = ASSIGNMENT_EDGE_CONTEXT.get(EdgeKinds.ASSIGNED_PERMISSION_SET_GROUP)
            if ctx:
                props.update(ctx)

            edges.append(_make_edge(user_id, psg_id, EdgeKinds.ASSIGNED_PERMISSION_SET_GROUP, props or None))

        return edges


    def build_permission_set_group_components(
        self,
        components: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        PermissionSetGroup -> PermissionSet
        sourced from PermissionSetGroupComponent
        """
        edges: List[Dict[str, Any]] = []

        for c in components.get("records", []):
            psg_id = c.get("PermissionSetGroupId")
            ps_id = c.get("PermissionSetId")
            if not psg_id or not ps_id:
                continue

            props = {}
            if c.get("Id"):
                props["PermissionSetGroupComponentId"] = c["Id"]
            sm = c.get("SystemModstamp") or c.get("SystemModStamp")
            if sm:
                props["SystemModstamp"] = sm

            # Source: ASSIGNMENT_EDGE_CONTEXT dict defined in this module
            ctx = ASSIGNMENT_EDGE_CONTEXT.get(EdgeKinds.INCLUDES_PERMISSION_SET)
            if ctx:
                props.update(ctx)

            edges.append(_make_edge(psg_id, ps_id, EdgeKinds.INCLUDES_PERMISSION_SET, props or None))

        return edges

    def build_role_assignments(self, users: Dict[str, Any]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        # Source: ASSIGNMENT_EDGE_CONTEXT dict defined in this module
        ctx = ASSIGNMENT_EDGE_CONTEXT.get(EdgeKinds.HAS_ROLE)
        for u in users.get("records", []):
            role_id = u.get("UserRoleId")
            if role_id:
                edges.append(_make_edge(u["Id"], role_id, EdgeKinds.HAS_ROLE, dict(ctx) if ctx else None))
        return edges

    def build_group_memberships(self, group_members: Dict[str, Any]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []

        def infer_member_kind(sf_id: str) -> str:
            if not sf_id:
                return "Unknown"
            if sf_id.startswith("005"):
                return "User"
            if sf_id.startswith("00G"):
                return "Group"
            return "Unknown"

        for gm in group_members.get("records", []):
            member = gm.get("UserOrGroupId")
            group = gm.get("GroupId")

            if not member or not group:
                continue

            props = {
                "GroupMemberId": gm.get("Id"),
                "MemberKind": infer_member_kind(member),
                "SystemModstamp": gm.get("SystemModstamp") or gm.get("SystemModStamp"),
            }
            props = {k: v for k, v in props.items() if v is not None}

            # Member -> Group (semantic direction)
            # Source: GROUP_AND_ACCESS_EDGE_CONTEXT dict defined in this module
            mem_ctx = GROUP_AND_ACCESS_EDGE_CONTEXT.get(EdgeKinds.MEMBER_OF_GROUP)
            mem_props = dict(props)
            if mem_ctx:
                mem_props.update(mem_ctx)
            edges.append(
                _make_edge(
                    member,
                    group,
                    EdgeKinds.MEMBER_OF_GROUP,
                    mem_props,
                )
            )

            # Group -> Member (UI-friendly so the Group "Members" panel can populate)
            # Source: GROUP_AND_ACCESS_EDGE_CONTEXT dict defined in this module
            has_ctx = GROUP_AND_ACCESS_EDGE_CONTEXT.get(EdgeKinds.HAS_MEMBER)
            has_props = dict(props)
            if has_ctx:
                has_props.update(has_ctx)
            edges.append(
                _make_edge(
                    group,
                    member,
                    EdgeKinds.HAS_MEMBER,
                    has_props,
                )
            )

        return edges

    # -------------------------
    # Role hierarchy
    # -------------------------

    def build_role_hierarchy(self, roles: Dict[str, Any]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        # Source: ASSIGNMENT_EDGE_CONTEXT dict defined in this module
        ctx = ASSIGNMENT_EDGE_CONTEXT.get(EdgeKinds.INHERITS_ROLE)
        for r in roles.get("records", []):
            parent = r.get("ParentRoleId")
            if parent:
                edges.append(_make_edge(r["Id"], parent, EdgeKinds.INHERITS_ROLE, dict(ctx) if ctx else None))
        return edges

    # -------------------------
    # Profile-owned PermissionSet link
    # -------------------------

    def build_profile_permission_sets(
        self,
        permission_sets: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        For PermissionSet records where IsOwnedByProfile=true, connect:
            ProfileId  -[OwnsPermissionSet]->  PermissionSetId
        """
        edges: List[Dict[str, Any]] = []
        # Source: ASSIGNMENT_EDGE_CONTEXT dict defined in this module
        ctx = ASSIGNMENT_EDGE_CONTEXT.get(EdgeKinds.HAS_PERMISSION_SET)
        for ps in permission_sets.get("records", []):
            if ps.get("IsOwnedByProfile") is not True:
                continue
            ps_id = ps.get("Id")
            profile_id = ps.get("ProfileId")
            if ps_id and profile_id:
                edges.append(_make_edge(profile_id, ps_id, EdgeKinds.HAS_PERMISSION_SET, dict(ctx) if ctx else None))
        return edges

    # -------------------------
    # System Permission Edges (to Organization)
    # -------------------------

    def build_permission_set_system_permissions(
        self,
        permission_sets: Dict[str, Any],
        org_node_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Connect PermissionSet -> Organization for every Permissions* flag that is True.
        Each system permission becomes an edge kind (e.g., ModifyAllData, ViewSetup).
        
        Args:
            permission_sets: PermissionSet records with Permissions* fields
            org_node_id: The Organization node ID
        
        Returns:
            List of edges from PermissionSets to Organization with permission as edge kind
        """
        edges: List[Dict[str, Any]] = []

        for ps in permission_sets.get("records", []):
            ps_id = ps.get("Id")
            if not ps_id:
                continue

            for field, value in ps.items():
                if not field.startswith("Permissions"):
                    continue
                if value is not True:
                    continue

                perm_name = field.removeprefix("Permissions")

                # Base properties: always include the permission name
                props: Dict[str, Any] = {"SystemPermission": perm_name}

                # Merge contextual description and impact for high-risk permissions
                # Source: SYSTEM_PERMISSION_CONTEXT dict defined in this module
                if perm_name in SYSTEM_PERMISSION_CONTEXT:
                    props.update(SYSTEM_PERMISSION_CONTEXT[perm_name])

                # Use the permission name as the edge kind
                edges.append(
                    _make_edge(
                        ps_id,
                        org_node_id,
                        perm_name,  # Edge kind is the permission name
                        props,
                    )
                )

        return edges

    def build_profile_system_permissions(
        self,
        profiles: Dict[str, Any],
        org_node_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Connect Profile -> Organization for each Permissions* flag that is True.
        Each system permission becomes an edge kind (e.g., ModifyAllData, ViewSetup).
        
        Args:
            profiles: Profile records with Permissions* fields
            org_node_id: The Organization node ID
        
        Returns:
            List of edges from Profiles to Organization with permission as edge kind
        """
        edges: List[Dict[str, Any]] = []

        for p in profiles.get("records", []):
            pid = p.get("Id")
            if not pid:
                continue

            for field, value in p.items():
                if not field.startswith("Permissions"):
                    continue
                if value is not True:
                    continue

                perm_name = field.removeprefix("Permissions")

                # Base properties: always include the permission name
                props: Dict[str, Any] = {"SystemPermission": perm_name}

                # Merge contextual description and impact for high-risk permissions
                # Source: SYSTEM_PERMISSION_CONTEXT dict defined in this module
                if perm_name in SYSTEM_PERMISSION_CONTEXT:
                    props.update(SYSTEM_PERMISSION_CONTEXT[perm_name])

                # Use the permission name as the edge kind
                edges.append(
                    _make_edge(
                        pid,
                        org_node_id,
                        perm_name,  # Edge kind is the permission name
                        props,
                    )
                )

        return edges

    # -------------------------
    # Queue Object Access
    # -------------------------

    def build_queue_object_access(self, queue_sobjects: Dict[str, Any], sobject_lookup: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Build edges showing which object types each Queue can own.
        
        Edge: Queue -[CanOwnObject]-> SFSObject
        
        Critical for privilege escalation: Queue members can access all records
        owned by the Queue for the specified object types.
        
        Properties include:
        - sobjectType: The object API name
        - QueueSobjectId: Junction record ID
        
        sobject_lookup: Maps SobjectType API name -> SFSObject node ID.
        Edges are skipped for any SObject type not present in the lookup
        (avoids dangling edges to objects not in the graph).
        """
        edges: List[Dict[str, Any]] = []
        _lookup = sobject_lookup or {}
        
        for qs in queue_sobjects.get("records", []):
            queue_id = qs.get("QueueId")
            sobject_type = qs.get("SobjectType")
            
            if not (queue_id and sobject_type):
                continue

            # Resolve to the actual SFSObject node ID; skip if not in our node set
            sobject_node_id = _lookup.get(sobject_type)
            if not sobject_node_id:
                continue
            
            props = {
                "sobjectType": sobject_type,
                "QueueSobjectId": qs.get("Id"),
                "SystemModstamp": qs.get("SystemModstamp"),
            }

            # Source: GROUP_AND_ACCESS_EDGE_CONTEXT dict defined in this module
            ctx = GROUP_AND_ACCESS_EDGE_CONTEXT.get(EdgeKinds.CAN_OWN_OBJECT)
            if ctx:
                props.update(ctx)

            edges.append(
                _make_edge(
                    queue_id,
                    sobject_node_id,
                    EdgeKinds.CAN_OWN_OBJECT,
                    props,
                )
            )
        
        return edges

    def build_record_ownership_edges(
        self,
        record_owners: list,
        sobject_lookup: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """
        Emit OwnsRecordsOfObject edges: SFUser -> SFSObject.

        record_owners: list returned by AssignmentExtractor.extract_record_owners —
            each entry is {"OwnerId": ..., "SobjectType": ..., "SobjectDurableId": ...}.
        sobject_lookup: QualifiedApiName -> DurableId (same dict used by CRUD edge builders).

        Deduplicates (owner, object) pairs so only one edge is emitted per user+object
        combination, regardless of how many records the user owns of that type.
        """
        edges: List[Dict[str, Any]] = []
        seen: Set[tuple] = set()
        ctx = GROUP_AND_ACCESS_EDGE_CONTEXT.get(EdgeKinds.OWNS_RECORDS_OF_OBJECT)

        for r in record_owners:
            owner_id = r.get("OwnerId")
            sobject_type = r.get("SobjectType")
            # Prefer the consistent DurableId from sobject_lookup so the edge target
            # always points to the same node ID used by CRUD and FLS edges.
            sobject_node_id = sobject_lookup.get(sobject_type) or r.get("SobjectDurableId")

            if not owner_id or not sobject_node_id:
                continue

            key = (_norm_sf_id(owner_id), _norm_sf_id(sobject_node_id))
            if key in seen:
                continue
            seen.add(key)

            props: Dict[str, Any] = {"SobjectType": sobject_type}
            if ctx:
                props.update(ctx)

            edges.append(_make_edge(owner_id, sobject_node_id, EdgeKinds.OWNS_RECORDS_OF_OBJECT, props))

        return edges

    def build_connected_app_creators(
        self, connected_apps: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Build CreatedBy edges from ConnectedApplication -> User.
        
        Shows which admin created each OAuth app, useful for:
        - Auditing app creation timeline
        - Identifying potential rogue apps created by compromised accounts
        - Understanding which admins have app creation privileges
        """
        edges: List[Dict[str, Any]] = []

        for app in connected_apps.get("records", []):
            app_id = app.get("Id")
            creator_id = app.get("CreatedById")

            if not app_id or not creator_id:
                continue

            props = {
                "CreatedDate": app.get("CreatedDate"),
            }

            # Source: GROUP_AND_ACCESS_EDGE_CONTEXT dict defined in this module
            ctx = GROUP_AND_ACCESS_EDGE_CONTEXT.get(EdgeKinds.CREATED_BY)
            if ctx:
                props.update(ctx)

            edges.append(
                _make_edge(
                    app_id,
                    creator_id,
                    EdgeKinds.CREATED_BY,
                    props,
                )
            )

        return edges

    def build_setup_entity_access(
        self, setup_entity_access: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Build CanAuthorize edges from Profile/PermissionSet -> ConnectedApplication.
        
        SetupEntityAccess grants Profiles/PermissionSets the ability to authorize apps.
        Users in these Profiles/PermSets can OAuth login to the ConnectedApp.
        
        Critical for attack paths:
        - Shows which users can authorize potentially risky OAuth apps
        - Identifies privilege escalation through app authorization
        - Maps OAuth access permissions across the org
        
        ParentId: PermissionSet ID (Profiles have PermissionSet representations)
        SetupEntityId: ConnectedApplication ID
        """
        edges: List[Dict[str, Any]] = []

        for access in setup_entity_access.get("records", []):
            parent_id = access.get("ParentId")  # Profile/PermissionSet
            entity_id = access.get("SetupEntityId")  # ConnectedApp
            entity_type = access.get("SetupEntityType")

            if not parent_id or not entity_id:
                continue

            # Only process ConnectedApplication type (should already be filtered in SOQL)
            if entity_type != "ConnectedApplication":
                continue

            props = {
                "SetupEntityType": entity_type,
                "SystemModstamp": access.get("SystemModstamp"),
                "SetupEntityAccessId": access.get("Id"),
            }

            # Source: GROUP_AND_ACCESS_EDGE_CONTEXT dict defined in this module
            ctx = GROUP_AND_ACCESS_EDGE_CONTEXT.get(EdgeKinds.CAN_AUTHORIZE)
            if ctx:
                props.update(ctx)

            edges.append(
                _make_edge(
                    parent_id,
                    entity_id,
                    EdgeKinds.CAN_AUTHORIZE,
                    props,
                )
            )

        return edges

    def build_object_permissions(
        self,
        object_permissions: Dict[str, Any],
        sobject_lookup: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """
        Build CRUD permission edges from Profile/PermissionSet -> SObject.
        
        ObjectPermissions grants CRUD access to SObjects.
        - ParentId: Profile or PermissionSet
        - SobjectType: Object API name (string like "Account", not ID)
        
        Creates 6 edge types based on permission flags:
        - CanCreate: Create new records
        - CanRead: Read records (respecting sharing)
        - CanEdit: Edit records (respecting sharing)
        - CanDelete: Delete records (respecting sharing)
        - CanViewAll: View ALL records (bypass sharing rules)
        - CanModifyAll: Edit/Delete ALL records (bypass sharing rules)
        
        Security notes:
        - ViewAll/ModifyAll are super-user permissions (bypass sharing)
        - Delete permission enables data destruction
        - Multiple edges per ObjectPermission record (one per enabled flag)
        
        sobject_lookup: Maps SobjectType API name -> EntityDefinition Id
        This allows us to create edges to the actual SObject nodes.
        """
        edges: List[Dict[str, Any]] = []

        for perm in object_permissions.get("records", []):
            parent_id = perm.get("ParentId")  # Profile/PermissionSet
            sobject_type = perm.get("SobjectType")  # API name like "Account"

            if not parent_id or not sobject_type:
                continue

            # Lookup the SObject node ID from the API name
            sobject_id = sobject_lookup.get(sobject_type)
            if not sobject_id:
                # SObject not in our node set (filtered out or doesn't exist)
                continue

            # Base properties for all edges
            base_props = {
                "SobjectType": sobject_type,
                "ObjectPermissionId": perm.get("Id"),
                "SystemModstamp": perm.get("SystemModstamp"),
            }

            # Create edges for each enabled permission
            permission_mappings = [
                ("PermissionsCreate", EdgeKinds.CAN_CREATE),
                ("PermissionsRead", EdgeKinds.CAN_READ),
                ("PermissionsEdit", EdgeKinds.CAN_EDIT),
                ("PermissionsDelete", EdgeKinds.CAN_DELETE),
                ("PermissionsViewAllRecords", EdgeKinds.CAN_VIEW_ALL),
                ("PermissionsModifyAllRecords", EdgeKinds.CAN_MODIFY_ALL),
            ]

            for perm_field, edge_kind in permission_mappings:
                if perm.get(perm_field):
                    props = base_props.copy()
                    props["PermissionType"] = perm_field

                    # Merge contextual description and impact for object CRUD permissions
                    # Source: OBJECT_PERMISSION_CONTEXT dict defined in this module
                    if edge_kind in OBJECT_PERMISSION_CONTEXT:
                        props.update(OBJECT_PERMISSION_CONTEXT[edge_kind])

                    edges.append(
                        _make_edge(
                            parent_id,
                            sobject_id,
                            edge_kind,
                            props,
                        )
                    )

        return edges
    def build_field_permissions(self, field_permissions):
        """
        Build Field-Level Security (FLS) edges from Profile/PermissionSet -> SFField.
        
        FieldPermissions grants access to individual fields within SObjects.
        - ParentId: Profile or PermissionSet
        - Field: Full field API name (e.g., "SecretData__c.HighlySensitiveField__c")
        
        Creates 2 edge types based on permission flags:
        - IsVisible: Field is visible AND editable (PermissionsEdit = True)
        - ReadOnly: Field is visible but read-only (PermissionsRead = True, PermissionsEdit = False)
        
        Security notes:
        - Field-level security is independent of object-level CRUD
        - Users can have Read on object but no access to specific fields
        - Sensitive fields (SSN, salary, PII) require FLS configuration
        - Missing FLS means field is inaccessible regardless of object permissions
        
        Edge modeling:
        - Source: Profile or PermissionSet (ParentId)
        - Target: SFField node (Field API name as node ID)
        - Edge type: IsVisible (edit)  or ReadOnly (read-only)
        """
        edges = []

        for perm in field_permissions.get("records", []):
            parent_id = perm.get("ParentId")  # Profile/PermissionSet
            field_name = perm.get("Field")  # Full field API name

            if not parent_id or not field_name:
                continue

            # Base properties for all edges
            base_props = {
                "SobjectType": perm.get("SobjectType"),
                "Field": field_name,
                "FieldPermissionId": perm.get("Id"),
                "SystemModstamp": perm.get("SystemModstamp"),
            }

            # Determine edge type based on permissions
            perm_edit = perm.get("PermissionsEdit", False)
            perm_read = perm.get("PermissionsRead", False)

            if perm_edit:
                # Edit permission implies read+write (IsVisible edge)
                props = base_props.copy()
                props["PermissionType"] = "PermissionsEdit"
                # Source: GROUP_AND_ACCESS_EDGE_CONTEXT dict defined in this module
                ctx = GROUP_AND_ACCESS_EDGE_CONTEXT.get(EdgeKinds.IS_VISIBLE)
                if ctx:
                    props.update(ctx)
                edges.append(
                    _make_edge(
                        parent_id,
                        field_name,  # Field name is the node ID
                        EdgeKinds.IS_VISIBLE,
                        props,
                    )
                )
            elif perm_read:
                # Read-only permission (ReadOnly edge)
                props = base_props.copy()
                props["PermissionType"] = "PermissionsRead"
                # Source: GROUP_AND_ACCESS_EDGE_CONTEXT dict defined in this module
                ctx = GROUP_AND_ACCESS_EDGE_CONTEXT.get(EdgeKinds.READ_ONLY)
                if ctx:
                    props.update(ctx)
                edges.append(
                    _make_edge(
                        parent_id,
                        field_name,  # Field name is the node ID
                        EdgeKinds.READ_ONLY,
                        props,
                    )
                )

        return edges
