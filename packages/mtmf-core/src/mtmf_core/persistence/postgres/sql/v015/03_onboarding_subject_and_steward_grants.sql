-- v015: privilege posture for the PR 23 onboarding transaction participants.
--
-- Both functions are installation/operator-only: owner-owned,
-- SECURITY INVOKER, fixed empty search_path, PUBLIC EXECUTE revoked, and
-- deliberately NOT granted to mtmf_runtime. No table or sequence privilege is
-- added. The functions are a transaction participant only; their future
-- privileged caller is an explicitly blocked PR 24P responsibility.

ALTER FUNCTION mtmf.onboarding_subject_prepare(text, text, uuid, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.onboarding_subject_prepare(text, text, uuid, uuid, uuid)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.onboarding_subject_prepare(text, text, uuid, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.onboarding_subject_prepare(text, text, uuid, uuid, uuid)
    FROM PUBLIC;

ALTER FUNCTION mtmf.onboarding_initial_steward_attach(uuid, text, text, uuid, uuid)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.onboarding_initial_steward_attach(uuid, text, text, uuid, uuid)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.onboarding_initial_steward_attach(uuid, text, text, uuid, uuid)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.onboarding_initial_steward_attach(uuid, text, text, uuid, uuid)
    FROM PUBLIC;
