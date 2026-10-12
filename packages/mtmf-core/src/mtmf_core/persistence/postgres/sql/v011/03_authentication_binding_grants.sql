-- v011: privilege posture for authentication bindings.
--
-- Mutation and guard functions are installation/operator-only: owner-owned,
-- SECURITY INVOKER, fixed empty search_path, PUBLIC EXECUTE revoked, and never
-- granted to mtmf_runtime. The two find-active reads are the only v011
-- functions granted to the restricted runtime.

ALTER FUNCTION mtmf.guard_service_credential_application() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_service_credential_application() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_service_credential_application() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_service_credential_application() FROM PUBLIC;

ALTER FUNCTION mtmf.guard_external_subject_identity() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.guard_external_subject_identity() SECURITY INVOKER;
ALTER FUNCTION mtmf.guard_external_subject_identity() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.guard_external_subject_identity() FROM PUBLIC;

ALTER FUNCTION mtmf.service_credential_application_add(uuid, text, text, uuid, smallint, timestamptz)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.service_credential_application_add(uuid, text, text, uuid, smallint, timestamptz)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.service_credential_application_add(uuid, text, text, uuid, smallint, timestamptz)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.service_credential_application_add(uuid, text, text, uuid, smallint, timestamptz)
    FROM PUBLIC;

ALTER FUNCTION mtmf.service_credential_application_revoke(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.service_credential_application_revoke(uuid) SECURITY INVOKER;
ALTER FUNCTION mtmf.service_credential_application_revoke(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.service_credential_application_revoke(uuid) FROM PUBLIC;

ALTER FUNCTION mtmf.external_subject_identity_add(uuid, text, text, uuid, smallint, timestamptz)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.external_subject_identity_add(uuid, text, text, uuid, smallint, timestamptz)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.external_subject_identity_add(uuid, text, text, uuid, smallint, timestamptz)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.external_subject_identity_add(uuid, text, text, uuid, smallint, timestamptz)
    FROM PUBLIC;

ALTER FUNCTION mtmf.external_subject_identity_revoke(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.external_subject_identity_revoke(uuid) SECURITY INVOKER;
ALTER FUNCTION mtmf.external_subject_identity_revoke(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.external_subject_identity_revoke(uuid) FROM PUBLIC;

-- Narrowly reviewed runtime reads.
ALTER FUNCTION mtmf.service_credential_application_find_active(text, text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.service_credential_application_find_active(text, text) SECURITY DEFINER;
ALTER FUNCTION mtmf.service_credential_application_find_active(text, text) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.service_credential_application_find_active(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.service_credential_application_find_active(text, text) TO mtmf_runtime;

ALTER FUNCTION mtmf.external_subject_identity_find_active(text, text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.external_subject_identity_find_active(text, text) SECURITY DEFINER;
ALTER FUNCTION mtmf.external_subject_identity_find_active(text, text) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.external_subject_identity_find_active(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.external_subject_identity_find_active(text, text) TO mtmf_runtime;
