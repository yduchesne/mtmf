-- v008: privilege posture for the root/stewardship objects.
--
-- The privileged structural functions are installation/operator-only:
-- owner-owned, SECURITY INVOKER, fixed empty search_path, PUBLIC EXECUTE
-- revoked, and deliberately NOT granted to mtmf_runtime. The replaced
-- tenant_add keeps its unchanged reviewed runtime signature. Trigger
-- functions are not callable entry points and are likewise not granted.

ALTER FUNCTION mtmf.stewardship_is_eligible(uuid, uuid, uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.stewardship_is_eligible(uuid, uuid, uuid) SECURITY INVOKER;
ALTER FUNCTION mtmf.stewardship_is_eligible(uuid, uuid, uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.stewardship_is_eligible(uuid, uuid, uuid) FROM PUBLIC;

ALTER FUNCTION mtmf.bootstrap_root(uuid, uuid, uuid, text, text, text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.bootstrap_root(uuid, uuid, uuid, text, text, text) SECURITY INVOKER;
ALTER FUNCTION mtmf.bootstrap_root(uuid, uuid, uuid, text, text, text) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.bootstrap_root(uuid, uuid, uuid, text, text, text) FROM PUBLIC;

ALTER FUNCTION mtmf.designate_steward(uuid, uuid, uuid, integer, text, text, text)
    OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.designate_steward(uuid, uuid, uuid, integer, text, text, text)
    SECURITY INVOKER;
ALTER FUNCTION mtmf.designate_steward(uuid, uuid, uuid, integer, text, text, text)
    SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.designate_steward(uuid, uuid, uuid, integer, text, text, text)
    FROM PUBLIC;

ALTER FUNCTION mtmf.activate_tenant(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.activate_tenant(uuid) SECURITY INVOKER;
ALTER FUNCTION mtmf.activate_tenant(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.activate_tenant(uuid) FROM PUBLIC;

ALTER FUNCTION mtmf.suspend_tenant(uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.suspend_tenant(uuid) SECURITY INVOKER;
ALTER FUNCTION mtmf.suspend_tenant(uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.suspend_tenant(uuid) FROM PUBLIC;

ALTER FUNCTION mtmf.recover_root_identity(uuid, text, text) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.recover_root_identity(uuid, text, text) SECURITY INVOKER;
ALTER FUNCTION mtmf.recover_root_identity(uuid, text, text) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.recover_root_identity(uuid, text, text) FROM PUBLIC;

-- The replaced tenant_add keeps the reviewed runtime grant (same signature).
ALTER FUNCTION mtmf.tenant_add(
    id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid,
    lifecycle_value smallint, deletion_status_value smallint, extension_value jsonb
) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_add(
    id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid,
    lifecycle_value smallint, deletion_status_value smallint, extension_value jsonb
) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_add(
    id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid,
    lifecycle_value smallint, deletion_status_value smallint, extension_value jsonb
) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_add(
    id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid,
    lifecycle_value smallint, deletion_status_value smallint, extension_value jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_add(
    id_value uuid, name_value text, scope_value smallint, owner_identity_id_value uuid,
    lifecycle_value smallint, deletion_status_value smallint, extension_value jsonb
) TO mtmf_runtime;
