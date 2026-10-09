-- v004: reviewed SECURITY DEFINER entry points and runtime grants.
--
-- Every repository function is owner-owned, SECURITY DEFINER, and pins
-- search_path to the empty string. PUBLIC EXECUTE is revoked and the
-- restricted runtime role receives EXECUTE on exactly the reviewed
-- signatures below. The runtime never receives a table, view, sequence,
-- or owner-default privilege.

ALTER FUNCTION mtmf.tenant_add(id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_add(id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_add(id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_add(id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_add(id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_get(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_get(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_get(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_get(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_get(id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.organization_add(id_value uuid, tenant_id_value uuid, name_value text, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.organization_add(id_value uuid, tenant_id_value uuid, name_value text, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.organization_add(id_value uuid, tenant_id_value uuid, name_value text, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.organization_add(id_value uuid, tenant_id_value uuid, name_value text, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.organization_add(id_value uuid, tenant_id_value uuid, name_value text, owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.organization_get(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.organization_get(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.organization_get(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.organization_get(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.organization_get(id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.organization_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.organization_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.organization_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.organization_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.organization_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.principal_add(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.principal_add(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.principal_add(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.principal_add(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.principal_add(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.principal_get(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.principal_get(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.principal_get(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.principal_get(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.principal_get(id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.principal_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.principal_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.principal_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.principal_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.principal_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_add(id_value uuid, principal_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_add(id_value uuid, principal_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_add(id_value uuid, principal_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_add(id_value uuid, principal_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_add(id_value uuid, principal_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_get(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_get(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_get(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_get(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_get(id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_add(id_value uuid, tenant_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_add(id_value uuid, tenant_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_add(id_value uuid, tenant_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_add(id_value uuid, tenant_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_add(id_value uuid, tenant_id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_get(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_get(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_get(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_get(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_get(id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_save(id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.action_add(urn_value text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.action_add(urn_value text) SECURITY DEFINER;
ALTER FUNCTION mtmf.action_add(urn_value text) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.action_add(urn_value text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.action_add(urn_value text) TO mtmf_runtime;

ALTER FUNCTION mtmf.action_get(urn_value text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.action_get(urn_value text) SECURITY DEFINER;
ALTER FUNCTION mtmf.action_get(urn_value text) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.action_get(urn_value text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.action_get(urn_value text) TO mtmf_runtime;

ALTER FUNCTION mtmf.role_add(payload_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.role_add(payload_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.role_add(payload_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.role_add(payload_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.role_add(payload_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.role_get(urn_value text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.role_get(urn_value text) SECURITY DEFINER;
ALTER FUNCTION mtmf.role_get(urn_value text) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.role_get(urn_value text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.role_get(urn_value text) TO mtmf_runtime;

ALTER FUNCTION mtmf.role_save(payload_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.role_save(payload_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.role_save(payload_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.role_save(payload_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.role_save(payload_value jsonb) TO mtmf_runtime;

ALTER FUNCTION mtmf.principal_tenant_membership_add(principal_id_value uuid, tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.principal_tenant_membership_add(principal_id_value uuid, tenant_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.principal_tenant_membership_add(principal_id_value uuid, tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.principal_tenant_membership_add(principal_id_value uuid, tenant_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.principal_tenant_membership_add(principal_id_value uuid, tenant_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.principal_tenant_membership_get(principal_id_value uuid, tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.principal_tenant_membership_get(principal_id_value uuid, tenant_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.principal_tenant_membership_get(principal_id_value uuid, tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.principal_tenant_membership_get(principal_id_value uuid, tenant_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.principal_tenant_membership_get(principal_id_value uuid, tenant_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.principal_tenant_membership_find_by_principal(principal_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.principal_tenant_membership_find_by_principal(principal_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.principal_tenant_membership_find_by_principal(principal_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.principal_tenant_membership_find_by_principal(principal_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.principal_tenant_membership_find_by_principal(principal_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.principal_tenant_membership_find_by_tenant(tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.principal_tenant_membership_find_by_tenant(tenant_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.principal_tenant_membership_find_by_tenant(tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.principal_tenant_membership_find_by_tenant(tenant_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.principal_tenant_membership_find_by_tenant(tenant_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_tenant_membership_add(identity_id_value uuid, tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_tenant_membership_add(identity_id_value uuid, tenant_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_tenant_membership_add(identity_id_value uuid, tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_tenant_membership_add(identity_id_value uuid, tenant_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_tenant_membership_add(identity_id_value uuid, tenant_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_tenant_membership_get(identity_id_value uuid, tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_tenant_membership_get(identity_id_value uuid, tenant_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_tenant_membership_get(identity_id_value uuid, tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_tenant_membership_get(identity_id_value uuid, tenant_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_tenant_membership_get(identity_id_value uuid, tenant_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_tenant_membership_find_by_identity(identity_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_tenant_membership_find_by_identity(identity_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_tenant_membership_find_by_identity(identity_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_tenant_membership_find_by_identity(identity_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_tenant_membership_find_by_identity(identity_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_tenant_membership_find_by_tenant(tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_tenant_membership_find_by_tenant(tenant_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_tenant_membership_find_by_tenant(tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_tenant_membership_find_by_tenant(tenant_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_tenant_membership_find_by_tenant(tenant_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_tenant_membership_add(group_id_value uuid, tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_tenant_membership_add(group_id_value uuid, tenant_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_tenant_membership_add(group_id_value uuid, tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_tenant_membership_add(group_id_value uuid, tenant_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_tenant_membership_add(group_id_value uuid, tenant_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_tenant_membership_get(group_id_value uuid, tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_tenant_membership_get(group_id_value uuid, tenant_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_tenant_membership_get(group_id_value uuid, tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_tenant_membership_get(group_id_value uuid, tenant_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_tenant_membership_get(group_id_value uuid, tenant_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_tenant_membership_find_by_group(group_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_tenant_membership_find_by_group(group_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_tenant_membership_find_by_group(group_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_tenant_membership_find_by_group(group_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_tenant_membership_find_by_group(group_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_tenant_membership_find_by_tenant(tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_tenant_membership_find_by_tenant(tenant_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_tenant_membership_find_by_tenant(tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_tenant_membership_find_by_tenant(tenant_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_tenant_membership_find_by_tenant(tenant_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_group_membership_add(identity_id_value uuid, group_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_group_membership_add(identity_id_value uuid, group_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_group_membership_add(identity_id_value uuid, group_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_group_membership_add(identity_id_value uuid, group_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_group_membership_add(identity_id_value uuid, group_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_group_membership_get(identity_id_value uuid, group_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_group_membership_get(identity_id_value uuid, group_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_group_membership_get(identity_id_value uuid, group_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_group_membership_get(identity_id_value uuid, group_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_group_membership_get(identity_id_value uuid, group_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_group_membership_find_by_identity(identity_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_group_membership_find_by_identity(identity_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_group_membership_find_by_identity(identity_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_group_membership_find_by_identity(identity_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_group_membership_find_by_identity(identity_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_group_membership_find_by_group(group_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_group_membership_find_by_group(group_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_group_membership_find_by_group(group_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_group_membership_find_by_group(group_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_group_membership_find_by_group(group_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_org_membership_add(identity_id_value uuid, organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_org_membership_add(identity_id_value uuid, organization_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_org_membership_add(identity_id_value uuid, organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_org_membership_add(identity_id_value uuid, organization_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_org_membership_add(identity_id_value uuid, organization_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_org_membership_get(identity_id_value uuid, organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_org_membership_get(identity_id_value uuid, organization_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_org_membership_get(identity_id_value uuid, organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_org_membership_get(identity_id_value uuid, organization_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_org_membership_get(identity_id_value uuid, organization_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_org_membership_find_by_identity(identity_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_org_membership_find_by_identity(identity_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_org_membership_find_by_identity(identity_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_org_membership_find_by_identity(identity_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_org_membership_find_by_identity(identity_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_org_membership_find_by_organization(organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_org_membership_find_by_organization(organization_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_org_membership_find_by_organization(organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_org_membership_find_by_organization(organization_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_org_membership_find_by_organization(organization_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_org_membership_add(group_id_value uuid, organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_org_membership_add(group_id_value uuid, organization_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_org_membership_add(group_id_value uuid, organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_org_membership_add(group_id_value uuid, organization_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_org_membership_add(group_id_value uuid, organization_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_org_membership_get(group_id_value uuid, organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_org_membership_get(group_id_value uuid, organization_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_org_membership_get(group_id_value uuid, organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_org_membership_get(group_id_value uuid, organization_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_org_membership_get(group_id_value uuid, organization_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_org_membership_find_by_group(group_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_org_membership_find_by_group(group_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_org_membership_find_by_group(group_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_org_membership_find_by_group(group_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_org_membership_find_by_group(group_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_org_membership_find_by_organization(organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_org_membership_find_by_organization(organization_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_org_membership_find_by_organization(organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_org_membership_find_by_organization(organization_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_org_membership_find_by_organization(organization_id_value uuid) TO mtmf_runtime;
