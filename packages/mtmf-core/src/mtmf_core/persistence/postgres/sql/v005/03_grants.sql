-- v005: reviewed Role-assignment entry points and runtime grants.
--
-- Every repository function is owner-owned with a fixed empty
-- ``search_path``. The SECURITY DEFINER entry points are separately
-- marked so they run as the table owner. The three validation helpers are
-- owner-owned but are deliberately NOT granted to the runtime role: they
-- are only reachable through the SECURITY DEFINER entry points.
--
-- PUBLIC EXECUTE is revoked from every v005 function and the restricted
-- runtime role receives EXECUTE on exactly the eight reviewed signatures.
-- The runtime never receives a table, sequence, or default privilege.

ALTER FUNCTION mtmf.role_assignment_validate_role(role_urn_value text, tenant_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.role_assignment_validate_role(role_urn_value text, tenant_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.role_assignment_validate_role(role_urn_value text, tenant_id_value uuid) FROM PUBLIC;

ALTER FUNCTION mtmf.identity_role_assignment_validate(tenant_id_value uuid, identity_id_value uuid, role_urn_value text, organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_role_assignment_validate(tenant_id_value uuid, identity_id_value uuid, role_urn_value text, organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_role_assignment_validate(tenant_id_value uuid, identity_id_value uuid, role_urn_value text, organization_id_value uuid) FROM PUBLIC;

ALTER FUNCTION mtmf.group_role_assignment_validate(tenant_id_value uuid, group_id_value uuid, role_urn_value text, organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_role_assignment_validate(tenant_id_value uuid, group_id_value uuid, role_urn_value text, organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_role_assignment_validate(tenant_id_value uuid, group_id_value uuid, role_urn_value text, organization_id_value uuid) FROM PUBLIC;

ALTER FUNCTION mtmf.identity_role_assignment_add(id_value uuid, tenant_id_value uuid, identity_id_value uuid, role_urn_value text, organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_role_assignment_add(id_value uuid, tenant_id_value uuid, identity_id_value uuid, role_urn_value text, organization_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_role_assignment_add(id_value uuid, tenant_id_value uuid, identity_id_value uuid, role_urn_value text, organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_role_assignment_add(id_value uuid, tenant_id_value uuid, identity_id_value uuid, role_urn_value text, organization_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_role_assignment_add(id_value uuid, tenant_id_value uuid, identity_id_value uuid, role_urn_value text, organization_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_role_assignment_get(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_role_assignment_get(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_role_assignment_get(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_role_assignment_get(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_role_assignment_get(id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_role_assignment_find_by_tenant_and_identity(tenant_id_value uuid, identity_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_role_assignment_find_by_tenant_and_identity(tenant_id_value uuid, identity_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_role_assignment_find_by_tenant_and_identity(tenant_id_value uuid, identity_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_role_assignment_find_by_tenant_and_identity(tenant_id_value uuid, identity_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_role_assignment_find_by_tenant_and_identity(tenant_id_value uuid, identity_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_role_assignment_remove(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_role_assignment_remove(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_role_assignment_remove(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_role_assignment_remove(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_role_assignment_remove(id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_role_assignment_add(id_value uuid, tenant_id_value uuid, group_id_value uuid, role_urn_value text, organization_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_role_assignment_add(id_value uuid, tenant_id_value uuid, group_id_value uuid, role_urn_value text, organization_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_role_assignment_add(id_value uuid, tenant_id_value uuid, group_id_value uuid, role_urn_value text, organization_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_role_assignment_add(id_value uuid, tenant_id_value uuid, group_id_value uuid, role_urn_value text, organization_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_role_assignment_add(id_value uuid, tenant_id_value uuid, group_id_value uuid, role_urn_value text, organization_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_role_assignment_get(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_role_assignment_get(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_role_assignment_get(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_role_assignment_get(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_role_assignment_get(id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_role_assignment_find_by_tenant_and_group(tenant_id_value uuid, group_id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_role_assignment_find_by_tenant_and_group(tenant_id_value uuid, group_id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_role_assignment_find_by_tenant_and_group(tenant_id_value uuid, group_id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_role_assignment_find_by_tenant_and_group(tenant_id_value uuid, group_id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_role_assignment_find_by_tenant_and_group(tenant_id_value uuid, group_id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.group_role_assignment_remove(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.group_role_assignment_remove(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.group_role_assignment_remove(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.group_role_assignment_remove(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.group_role_assignment_remove(id_value uuid) TO mtmf_runtime;
