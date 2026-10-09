-- v003: reviewed SECURITY DEFINER entry points for membership removal.
--
-- The six membership-removal functions from v002 remain byte-for-byte
-- unchanged. This additive migration re-asserts owner ownership and a
-- fixed empty search path, converts them to SECURITY DEFINER (so they can
-- perform the trusted table deletes and audit insert as mtmf_owner), and
-- grants EXECUTE to the restricted runtime role on exactly these six
-- signatures.
--
-- The bodies already schema-qualify every referenced table/function, use no
-- dynamic SQL, derive Tenant scope from authoritative entity rows (never a
-- caller-supplied Tenant alone), keep their row locks, cascade, actual
-- affected-row counts, no-op semantics, and single atomic audit insert.
-- SECURITY DEFINER elevates database capability only; it is not
-- application authorization (see docs/DATABASE.md section 6).

ALTER FUNCTION mtmf.remove_principal_tenant_membership(uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.remove_principal_tenant_membership(uuid, uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.remove_principal_tenant_membership(uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.remove_principal_tenant_membership(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.remove_principal_tenant_membership(uuid, uuid, uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.remove_identity_tenant_membership(uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.remove_identity_tenant_membership(uuid, uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.remove_identity_tenant_membership(uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.remove_identity_tenant_membership(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.remove_identity_tenant_membership(uuid, uuid, uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.remove_group_tenant_membership(uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.remove_group_tenant_membership(uuid, uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.remove_group_tenant_membership(uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.remove_group_tenant_membership(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.remove_group_tenant_membership(uuid, uuid, uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.remove_identity_group_membership(uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.remove_identity_group_membership(uuid, uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.remove_identity_group_membership(uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.remove_identity_group_membership(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.remove_identity_group_membership(uuid, uuid, uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.remove_identity_org_membership(uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.remove_identity_org_membership(uuid, uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.remove_identity_org_membership(uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.remove_identity_org_membership(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.remove_identity_org_membership(uuid, uuid, uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.remove_group_org_membership(uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.remove_group_org_membership(uuid, uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.remove_group_org_membership(uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.remove_group_org_membership(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.remove_group_org_membership(uuid, uuid, uuid)
    TO mtmf_runtime;
