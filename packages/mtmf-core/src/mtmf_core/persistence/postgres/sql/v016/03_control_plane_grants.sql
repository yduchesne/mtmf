-- v016: ownership and PUBLIC denial. Control-role grants are a separate
-- opt-in installation phase and MUST NOT appear here.

ALTER FUNCTION mtmf.pr24p_require_operator(uuid, uuid, text, text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.pr24p_require_exact_permission(text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.pr24p_entitlement_json(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_system_operator_assignment() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_append_only() OWNER TO mtmf_owner;

ALTER FUNCTION mtmf.pr24p_require_operator(uuid, uuid, text, text) SECURITY INVOKER;
ALTER FUNCTION mtmf.pr24p_require_operator(uuid, uuid, text, text) SET search_path = '';
ALTER FUNCTION mtmf.pr24p_require_exact_permission(text) SECURITY INVOKER;
ALTER FUNCTION mtmf.pr24p_require_exact_permission(text) SET search_path = '';
ALTER FUNCTION mtmf.pr24p_entitlement_json(uuid) SECURITY INVOKER;
ALTER FUNCTION mtmf.pr24p_entitlement_json(uuid) SET search_path = '';
ALTER FUNCTION mtmf.guard_system_operator_assignment() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_system_operator_assignment() SET search_path = '';
ALTER FUNCTION mtmf.guard_append_only() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_append_only() SET search_path = '';

REVOKE ALL ON FUNCTION mtmf.pr24p_require_operator(uuid, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mtmf.pr24p_require_exact_permission(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mtmf.pr24p_entitlement_json(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION mtmf.guard_system_operator_assignment() FROM PUBLIC;
REVOKE ALL ON FUNCTION mtmf.guard_append_only() FROM PUBLIC;

ALTER FUNCTION mtmf.control_operator_authorization_snapshot(uuid, uuid, text, text, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.control_operator_authorization_snapshot(uuid, uuid, text, text, uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.control_operator_authorization_snapshot(uuid, uuid, text, text, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.control_operator_authorization_snapshot(uuid, uuid, text, text, uuid, uuid)
    FROM PUBLIC;

ALTER FUNCTION mtmf.control_entitlement_grant(uuid, uuid, text, text, uuid, uuid, bigint, text, uuid, bytea)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.control_entitlement_grant(uuid, uuid, text, text, uuid, uuid, bigint, text, uuid, bytea)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.control_entitlement_grant(uuid, uuid, text, text, uuid, uuid, bigint, text, uuid, bytea)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.control_entitlement_grant(uuid, uuid, text, text, uuid, uuid, bigint, text, uuid, bytea)
    FROM PUBLIC;

ALTER FUNCTION mtmf.control_entitlement_revoke(uuid, uuid, text, text, uuid, uuid, text, uuid, bytea)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.control_entitlement_revoke(uuid, uuid, text, text, uuid, uuid, text, uuid, bytea)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.control_entitlement_revoke(uuid, uuid, text, text, uuid, uuid, text, uuid, bytea)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.control_entitlement_revoke(uuid, uuid, text, text, uuid, uuid, text, uuid, bytea)
    FROM PUBLIC;

ALTER FUNCTION mtmf.control_entitlement_get(uuid, uuid, text, text, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.control_entitlement_get(uuid, uuid, text, text, uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.control_entitlement_get(uuid, uuid, text, text, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.control_entitlement_get(uuid, uuid, text, text, uuid, uuid)
    FROM PUBLIC;

ALTER FUNCTION mtmf.control_pre_tenant_admission_read(uuid, text, text)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.control_pre_tenant_admission_read(uuid, text, text)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.control_pre_tenant_admission_read(uuid, text, text)
    STABLE;
ALTER FUNCTION mtmf.control_pre_tenant_admission_read(uuid, text, text)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.control_pre_tenant_admission_read(uuid, text, text)
    FROM PUBLIC;
