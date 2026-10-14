-- v012: privilege posture (PR 19C).
--
-- The policy seed and audit guard are installation/operator-only (owner-owned,
-- SECURITY INVOKER, PUBLIC revoked, never runtime-granted). The bounded lock
-- helper and the audited membership-add function are the only two v012
-- functions granted to the restricted runtime, and the legacy unaudited
-- runtime grant on ``identity_group_membership_add(uuid, uuid)`` is revoked so
-- no unaudited bypass remains.

ALTER FUNCTION mtmf.guard_security_mutation_audit() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_security_mutation_audit() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_security_mutation_audit() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_security_mutation_audit() FROM PUBLIC;

ALTER FUNCTION mtmf.install_membership_add_policy() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.install_membership_add_policy() SECURITY INVOKER;
ALTER FUNCTION mtmf.install_membership_add_policy() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.install_membership_add_policy() FROM PUBLIC;

-- Bounded row-lock/recheck helper (Amendment 01 §D).
ALTER FUNCTION mtmf.identity_group_membership_add_lock(uuid, uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_group_membership_add_lock(uuid, uuid, uuid, uuid)
    SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_group_membership_add_lock(uuid, uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_group_membership_add_lock(uuid, uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_group_membership_add_lock(uuid, uuid, uuid, uuid)
    TO mtmf_runtime;

-- Audited membership-add entry point.
ALTER FUNCTION mtmf.identity_group_membership_add_verified(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, text, text, uuid, timestamptz
) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_group_membership_add_verified(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, text, text, uuid, timestamptz
) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_group_membership_add_verified(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, text, text, uuid, timestamptz
) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_group_membership_add_verified(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, text, text, uuid, timestamptz
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_group_membership_add_verified(
    uuid, uuid, uuid, uuid, uuid, uuid, uuid, text, text, uuid, timestamptz
) TO mtmf_runtime;

-- Close the legacy unaudited runtime bypass. The function definition is
-- preserved for migration/history/operator compatibility, but neither
-- mtmf_runtime nor PUBLIC may execute it, and it is demoted to SECURITY
-- INVOKER so the reviewed "every SECURITY DEFINER function is runtime-granted"
-- posture remains exact. Owner/operator callers continue to have access.
ALTER FUNCTION mtmf.identity_group_membership_add(uuid, uuid) SECURITY INVOKER;
REVOKE ALL ON FUNCTION mtmf.identity_group_membership_add(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION mtmf.identity_group_membership_add(uuid, uuid) FROM mtmf_runtime;
