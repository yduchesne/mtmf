-- v007: entity read/write functions carrying origin and lifecycle.
--
-- The changed signatures (tenant_add/tenant_save/identity_add) replace the
-- v004 overloads, so the old signatures are dropped first; their runtime
-- grants disappear with them and the new exact signatures are granted in
-- 03. tenant_get/identity_get keep their signatures and only gain the new
-- payload fields. identity_save is unchanged because origin is immutable.

DROP FUNCTION IF EXISTS mtmf.tenant_add(uuid, text, smallint, uuid, smallint, jsonb);
DROP FUNCTION IF EXISTS mtmf.tenant_save(uuid, text, smallint, jsonb);
DROP FUNCTION IF EXISTS mtmf.identity_add(uuid, uuid, text, smallint, jsonb);

CREATE OR REPLACE FUNCTION mtmf.tenant_add(
    id_value uuid,
    name_value text,
    scope_value smallint,
    owner_identity_id_value uuid,
    lifecycle_value smallint,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH inserted AS (
        INSERT INTO mtmf.tenant (
            id, name, scope, owner_identity_id, lifecycle, deletion_status, extension
        )
        VALUES (
            id_value,
            name_value,
            scope_value,
            owner_identity_id_value,
            lifecycle_value,
            deletion_status_value,
            extension_value
        )
        ON CONFLICT (id) DO NOTHING
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM inserted);
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'name', name,
        'scope', scope,
        'owner_identity_id', owner_identity_id,
        'lifecycle', lifecycle,
        'deletion_status', deletion_status,
        'extension', extension
    )
    FROM mtmf.tenant
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_save(
    id_value uuid,
    name_value text,
    lifecycle_value smallint,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH updated AS (
        UPDATE mtmf.tenant
        SET name = name_value,
            lifecycle = lifecycle_value,
            deletion_status = deletion_status_value,
            extension = extension_value
        WHERE id = id_value
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM updated);
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_add(
    id_value uuid,
    principal_id_value uuid,
    name_value text,
    origin_value smallint,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH inserted AS (
        INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status, extension)
        VALUES (
            id_value,
            principal_id_value,
            name_value,
            origin_value,
            deletion_status_value,
            extension_value
        )
        ON CONFLICT (id) DO NOTHING
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM inserted);
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'principal_id', principal_id,
        'name', name,
        'origin', origin,
        'deletion_status', deletion_status,
        'extension', extension
    )
    FROM mtmf.identity
    WHERE id = id_value;
$$;
