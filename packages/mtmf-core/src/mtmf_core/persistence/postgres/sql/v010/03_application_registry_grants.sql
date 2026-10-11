-- v010: privilege posture for the Application registry (PR 13).
--
-- Privileged mutation and guard functions are installation/operator-only:
-- owner-owned, SECURITY INVOKER, fixed empty search_path, PUBLIC EXECUTE
-- revoked, and deliberately NOT granted to mtmf_runtime. The eight narrowly
-- reviewed runtime reads are SECURITY DEFINER with a fixed empty search_path
-- and are the only v010 functions granted to mtmf_runtime.

-- Guard functions (private; never runtime-granted).
ALTER FUNCTION mtmf.guard_application_registry_application() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_application_registry_application() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_application_registry_application() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_application_registry_application() FROM PUBLIC;

ALTER FUNCTION mtmf.guard_application_tenant_registration() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_application_tenant_registration() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_application_tenant_registration() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_application_tenant_registration() FROM PUBLIC;

ALTER FUNCTION mtmf.guard_tenant_application_subscription() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_tenant_application_subscription() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_tenant_application_subscription() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_tenant_application_subscription() FROM PUBLIC;

-- Privileged mutation (never runtime-granted).
ALTER FUNCTION mtmf.application_add(uuid, text, text, uuid, smallint, jsonb)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_add(uuid, text, text, uuid, smallint, jsonb)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.application_add(uuid, text, text, uuid, smallint, jsonb)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_add(uuid, text, text, uuid, smallint, jsonb)
    FROM PUBLIC;

ALTER FUNCTION mtmf.application_save(uuid, text, smallint, jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_save(uuid, text, smallint, jsonb) SECURITY INVOKER;
ALTER FUNCTION mtmf.application_save(uuid, text, smallint, jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_save(uuid, text, smallint, jsonb) FROM PUBLIC;

ALTER FUNCTION mtmf.application_tenant_registration_add(uuid, uuid, uuid, uuid, smallint, timestamptz)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_tenant_registration_add(uuid, uuid, uuid, uuid, smallint, timestamptz)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.application_tenant_registration_add(uuid, uuid, uuid, uuid, smallint, timestamptz)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_tenant_registration_add(uuid, uuid, uuid, uuid, smallint, timestamptz)
    FROM PUBLIC;

ALTER FUNCTION mtmf.application_tenant_registration_save(uuid, smallint) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_tenant_registration_save(uuid, smallint) SECURITY INVOKER;
ALTER FUNCTION mtmf.application_tenant_registration_save(uuid, smallint) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_tenant_registration_save(uuid, smallint) FROM PUBLIC;

ALTER FUNCTION mtmf.tenant_application_subscription_add(uuid, uuid, uuid, uuid, smallint, timestamptz, timestamptz, timestamptz)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_application_subscription_add(uuid, uuid, uuid, uuid, smallint, timestamptz, timestamptz, timestamptz)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.tenant_application_subscription_add(uuid, uuid, uuid, uuid, smallint, timestamptz, timestamptz, timestamptz)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_application_subscription_add(uuid, uuid, uuid, uuid, smallint, timestamptz, timestamptz, timestamptz)
    FROM PUBLIC;

ALTER FUNCTION mtmf.tenant_application_subscription_save(uuid, smallint, timestamptz)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_application_subscription_save(uuid, smallint, timestamptz)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.tenant_application_subscription_save(uuid, smallint, timestamptz)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_application_subscription_save(uuid, smallint, timestamptz)
    FROM PUBLIC;

-- Narrowly reviewed runtime reads.
ALTER FUNCTION mtmf.application_get(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_get(uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.application_get(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_get(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.application_get(uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.application_get_by_key(text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_get_by_key(text) SECURITY DEFINER;
ALTER FUNCTION mtmf.application_get_by_key(text) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_get_by_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.application_get_by_key(text) TO mtmf_runtime;

ALTER FUNCTION mtmf.application_tenant_registration_get(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_tenant_registration_get(uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.application_tenant_registration_get(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_tenant_registration_get(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.application_tenant_registration_get(uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.application_tenant_registration_find_by_application_and_tenant(uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_tenant_registration_find_by_application_and_tenant(uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.application_tenant_registration_find_by_application_and_tenant(uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_tenant_registration_find_by_application_and_tenant(uuid, uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.application_tenant_registration_find_by_application_and_tenant(uuid, uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.application_tenant_registration_find_by_tenant(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_tenant_registration_find_by_tenant(uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.application_tenant_registration_find_by_tenant(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_tenant_registration_find_by_tenant(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.application_tenant_registration_find_by_tenant(uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_application_subscription_get(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_application_subscription_get(uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_application_subscription_get(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_application_subscription_get(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_application_subscription_get(uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_application_subscription_find_by_application_and_tenant(uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_application_subscription_find_by_application_and_tenant(uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_application_subscription_find_by_application_and_tenant(uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_application_subscription_find_by_application_and_tenant(uuid, uuid)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_application_subscription_find_by_application_and_tenant(uuid, uuid)
    TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_application_subscription_find_by_tenant(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_application_subscription_find_by_tenant(uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_application_subscription_find_by_tenant(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_application_subscription_find_by_tenant(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_application_subscription_find_by_tenant(uuid) TO mtmf_runtime;
