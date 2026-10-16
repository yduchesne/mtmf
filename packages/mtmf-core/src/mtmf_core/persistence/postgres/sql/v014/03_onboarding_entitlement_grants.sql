-- v014: privilege posture for the onboarding entitlement foundation (PR 22).
--
-- Every function in v014 is operator/installation-only: owner-owned,
-- SECURITY INVOKER, fixed empty search_path, PUBLIC EXECUTE revoked, and
-- deliberately NOT granted to mtmf_runtime. There is no runtime-callable
-- entitlement function in PR 22; the pre-Tenant admission runtime read surface
-- belongs to the BLOCKED composite seam (see PR22_STOP_REPORT.md). The two
-- tables carry no runtime table privilege.

ALTER FUNCTION mtmf.guard_application_onboarding_entitlement() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_application_onboarding_entitlement() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_application_onboarding_entitlement() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_application_onboarding_entitlement() FROM PUBLIC;

ALTER FUNCTION mtmf.guard_application_onboarding_entitlement_event() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_application_onboarding_entitlement_event() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_application_onboarding_entitlement_event() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_application_onboarding_entitlement_event() FROM PUBLIC;

ALTER FUNCTION mtmf.application_onboarding_entitlement_grant(
    uuid, uuid, uuid, text, bigint, uuid
) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_onboarding_entitlement_grant(
    uuid, uuid, uuid, text, bigint, uuid
) SECURITY INVOKER;
ALTER FUNCTION mtmf.application_onboarding_entitlement_grant(
    uuid, uuid, uuid, text, bigint, uuid
) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_onboarding_entitlement_grant(
    uuid, uuid, uuid, text, bigint, uuid
) FROM PUBLIC;

ALTER FUNCTION mtmf.application_onboarding_entitlement_revoke(uuid, uuid, text, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_onboarding_entitlement_revoke(uuid, uuid, text, uuid)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.application_onboarding_entitlement_revoke(uuid, uuid, text, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_onboarding_entitlement_revoke(uuid, uuid, text, uuid)
    FROM PUBLIC;

ALTER FUNCTION mtmf.application_onboarding_entitlement_get(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_onboarding_entitlement_get(uuid) SECURITY INVOKER;
ALTER FUNCTION mtmf.application_onboarding_entitlement_get(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_onboarding_entitlement_get(uuid) FROM PUBLIC;

ALTER FUNCTION mtmf.application_onboarding_entitlement_find_by_application(uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_onboarding_entitlement_find_by_application(uuid)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.application_onboarding_entitlement_find_by_application(uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_onboarding_entitlement_find_by_application(uuid)
    FROM PUBLIC;

ALTER FUNCTION mtmf.application_onboarding_entitlement_event_find_by_entitlement(uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.application_onboarding_entitlement_event_find_by_entitlement(uuid)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.application_onboarding_entitlement_event_find_by_entitlement(uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.application_onboarding_entitlement_event_find_by_entitlement(uuid)
    FROM PUBLIC;
