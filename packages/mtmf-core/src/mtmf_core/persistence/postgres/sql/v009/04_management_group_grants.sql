-- v009: privilege posture for the TenantManagementGroup objects.
--
-- Privileged mutation and guard functions are installation/operator-only:
-- owner-owned, SECURITY INVOKER, fixed empty search_path, PUBLIC EXECUTE
-- revoked, and deliberately NOT granted to mtmf_runtime. The narrowly
-- reviewed runtime reads are SECURITY DEFINER with a fixed empty search_path
-- and are the only v009 functions granted to mtmf_runtime.

ALTER FUNCTION mtmf.guard_tenant_management_group() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_tenant_management_group() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_tenant_management_group() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_tenant_management_group() FROM PUBLIC;

ALTER FUNCTION mtmf.guard_tenant_management_group_membership() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_tenant_management_group_membership() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_tenant_management_group_membership() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_tenant_management_group_membership() FROM PUBLIC;

ALTER FUNCTION mtmf.guard_tenant_management_group_actor_eligibility() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_tenant_management_group_actor_eligibility() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_tenant_management_group_actor_eligibility() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_tenant_management_group_actor_eligibility() FROM PUBLIC;

ALTER FUNCTION mtmf.create_root_management_group() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.create_root_management_group() SECURITY INVOKER;
ALTER FUNCTION mtmf.create_root_management_group() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.create_root_management_group() FROM PUBLIC;

ALTER FUNCTION mtmf.initialize_root_tenant_management_group(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.initialize_root_tenant_management_group(uuid) SECURITY INVOKER;
ALTER FUNCTION mtmf.initialize_root_tenant_management_group(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.initialize_root_tenant_management_group(uuid) FROM PUBLIC;

ALTER FUNCTION mtmf.create_tenant_management_group(uuid, uuid, text, smallint)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.create_tenant_management_group(uuid, uuid, text, smallint)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.create_tenant_management_group(uuid, uuid, text, smallint)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.create_tenant_management_group(uuid, uuid, text, smallint)
    FROM PUBLIC;

ALTER FUNCTION mtmf.add_tenant_management_group_membership(uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.add_tenant_management_group_membership(uuid, uuid, uuid)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.add_tenant_management_group_membership(uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.add_tenant_management_group_membership(uuid, uuid, uuid)
    FROM PUBLIC;

ALTER FUNCTION mtmf.remove_tenant_management_group_membership(uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.remove_tenant_management_group_membership(uuid, uuid)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.remove_tenant_management_group_membership(uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.remove_tenant_management_group_membership(uuid, uuid)
    FROM PUBLIC;

ALTER FUNCTION mtmf.add_tenant_management_group_actor_eligibility(uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.add_tenant_management_group_actor_eligibility(uuid, uuid, uuid)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.add_tenant_management_group_actor_eligibility(uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.add_tenant_management_group_actor_eligibility(uuid, uuid, uuid)
    FROM PUBLIC;

ALTER FUNCTION mtmf.remove_tenant_management_group_actor_eligibility(uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.remove_tenant_management_group_actor_eligibility(uuid, uuid)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.remove_tenant_management_group_actor_eligibility(uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.remove_tenant_management_group_actor_eligibility(uuid, uuid)
    FROM PUBLIC;

ALTER FUNCTION mtmf.install_management_roles() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.install_management_roles() SECURITY INVOKER;
ALTER FUNCTION mtmf.install_management_roles() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.install_management_roles() FROM PUBLIC;

-- Narrowly reviewed runtime reads.
ALTER FUNCTION mtmf.tenant_management_group_get(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_management_group_get(uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_management_group_get(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_management_group_get(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_management_group_get(uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_management_group_find_by_manager(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_management_group_find_by_manager(uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_management_group_find_by_manager(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_management_group_find_by_manager(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_management_group_find_by_manager(uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_management_group_membership_find_by_group(uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_management_group_membership_find_by_group(uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_management_group_membership_find_by_group(uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_management_group_membership_find_by_group(uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_management_group_membership_find_by_group(uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_management_group_membership_find_by_tenant(uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_management_group_membership_find_by_tenant(uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_management_group_membership_find_by_tenant(uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_management_group_membership_find_by_tenant(uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_management_group_membership_find_by_tenant(uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_management_group_membership_get(uuid, uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_management_group_membership_get(uuid, uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_management_group_membership_get(uuid, uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_management_group_membership_get(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_management_group_membership_get(uuid, uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_management_group_actor_eligibility_get(uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_management_group_actor_eligibility_get(uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_management_group_actor_eligibility_get(uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_management_group_actor_eligibility_get(uuid, uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_management_group_actor_eligibility_get(uuid, uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_identity(uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_identity(uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_identity(uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_identity(uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_identity(uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_group(uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_group(uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_group(uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_group(uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_management_group_actor_eligibility_find_by_group(uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.root_registry_get() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.root_registry_get() SECURITY DEFINER;
ALTER FUNCTION mtmf.root_registry_get() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.root_registry_get() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.root_registry_get() TO mtmf_runtime;
