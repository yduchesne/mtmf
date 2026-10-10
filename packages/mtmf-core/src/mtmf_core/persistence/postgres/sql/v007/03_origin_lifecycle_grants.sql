-- v007: exact runtime grants for the changed entity signatures.
--
-- The dropped v004 overloads lose their grants automatically. The new
-- tenant_add/tenant_save/identity_add signatures and the updated (same
-- signature) tenant_get/identity_get are re-asserted owner-owned,
-- SECURITY DEFINER, fixed empty search_path, PUBLIC-revoked, and granted to
-- exactly the restricted runtime role.

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

ALTER FUNCTION mtmf.tenant_get(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_get(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_get(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_get(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_get(id_value uuid) TO mtmf_runtime;

ALTER FUNCTION mtmf.tenant_save(
    id_value uuid, name_value text, lifecycle_value smallint,
    deletion_status_value smallint, extension_value jsonb
) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.tenant_save(
    id_value uuid, name_value text, lifecycle_value smallint,
    deletion_status_value smallint, extension_value jsonb
) SECURITY DEFINER;
ALTER FUNCTION mtmf.tenant_save(
    id_value uuid, name_value text, lifecycle_value smallint,
    deletion_status_value smallint, extension_value jsonb
) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.tenant_save(
    id_value uuid, name_value text, lifecycle_value smallint,
    deletion_status_value smallint, extension_value jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.tenant_save(
    id_value uuid, name_value text, lifecycle_value smallint,
    deletion_status_value smallint, extension_value jsonb
) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_add(
    id_value uuid, principal_id_value uuid, name_value text, origin_value smallint,
    deletion_status_value smallint, extension_value jsonb
) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_add(
    id_value uuid, principal_id_value uuid, name_value text, origin_value smallint,
    deletion_status_value smallint, extension_value jsonb
) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_add(
    id_value uuid, principal_id_value uuid, name_value text, origin_value smallint,
    deletion_status_value smallint, extension_value jsonb
) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_add(
    id_value uuid, principal_id_value uuid, name_value text, origin_value smallint,
    deletion_status_value smallint, extension_value jsonb
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_add(
    id_value uuid, principal_id_value uuid, name_value text, origin_value smallint,
    deletion_status_value smallint, extension_value jsonb
) TO mtmf_runtime;

ALTER FUNCTION mtmf.identity_get(id_value uuid) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.identity_get(id_value uuid) SECURITY DEFINER;
ALTER FUNCTION mtmf.identity_get(id_value uuid) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.identity_get(id_value uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.identity_get(id_value uuid) TO mtmf_runtime;
