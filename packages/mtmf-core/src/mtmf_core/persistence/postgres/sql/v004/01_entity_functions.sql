-- v004: repository read/write functions for UUID-identified entities.
--
-- Each function is owner-owned, SECURITY DEFINER, pins search_path to the
-- empty string, and schema-qualifies every relation. The restricted
-- runtime login is granted EXECUTE on exactly the reviewed signatures in
-- 09_grants.sql; it has no direct table or sequence privilege.
--
-- Contract per operation:
--   *_add   -> INSERT ... ON CONFLICT DO NOTHING; returns false when the
--              immutable identity already exists (committed or staged in
--              the caller's transaction), never raises for a duplicate.
--   *_get   -> returns a detached JSON object, or SQL NULL when absent.
--   *_save  -> UPDATE only; returns false when the identity is unknown.
--              Mutable columns update; identity/provenance columns are
--              never written, so the v001 immutability triggers hold.

CREATE OR REPLACE FUNCTION mtmf.tenant_add(
    id_value uuid,
    name_value text,
    scope_value smallint,
    owner_identity_id_value uuid,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH inserted AS (
        INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, deletion_status, extension)
        VALUES (
            id_value,
            name_value,
            scope_value,
            owner_identity_id_value,
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
        'deletion_status', deletion_status,
        'extension', extension
    )
    FROM mtmf.tenant
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.tenant_save(
    id_value uuid,
    name_value text,
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
            deletion_status = deletion_status_value,
            extension = extension_value
        WHERE id = id_value
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM updated);
$$;

CREATE OR REPLACE FUNCTION mtmf.organization_add(
    id_value uuid,
    tenant_id_value uuid,
    name_value text,
    owner_identity_id_value uuid,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH inserted AS (
        INSERT INTO mtmf.organization (
            id, tenant_id, name, owner_identity_id, deletion_status, extension
        )
        VALUES (
            id_value,
            tenant_id_value,
            name_value,
            owner_identity_id_value,
            deletion_status_value,
            extension_value
        )
        ON CONFLICT (id) DO NOTHING
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM inserted);
$$;

CREATE OR REPLACE FUNCTION mtmf.organization_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'tenant_id', tenant_id,
        'name', name,
        'owner_identity_id', owner_identity_id,
        'deletion_status', deletion_status,
        'extension', extension
    )
    FROM mtmf.organization
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.organization_save(
    id_value uuid,
    name_value text,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH updated AS (
        UPDATE mtmf.organization
        SET name = name_value,
            deletion_status = deletion_status_value,
            extension = extension_value
        WHERE id = id_value
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM updated);
$$;

CREATE OR REPLACE FUNCTION mtmf.principal_add(
    id_value uuid,
    name_value text,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH inserted AS (
        INSERT INTO mtmf.principal (id, name, deletion_status, extension)
        VALUES (id_value, name_value, deletion_status_value, extension_value)
        ON CONFLICT (id) DO NOTHING
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM inserted);
$$;

CREATE OR REPLACE FUNCTION mtmf.principal_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'name', name,
        'deletion_status', deletion_status,
        'extension', extension
    )
    FROM mtmf.principal
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.principal_save(
    id_value uuid,
    name_value text,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH updated AS (
        UPDATE mtmf.principal
        SET name = name_value,
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
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH inserted AS (
        INSERT INTO mtmf.identity (id, principal_id, name, deletion_status, extension)
        VALUES (id_value, principal_id_value, name_value, deletion_status_value, extension_value)
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
        'deletion_status', deletion_status,
        'extension', extension
    )
    FROM mtmf.identity
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.identity_save(
    id_value uuid,
    name_value text,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH updated AS (
        UPDATE mtmf.identity
        SET name = name_value,
            deletion_status = deletion_status_value,
            extension = extension_value
        WHERE id = id_value
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM updated);
$$;

CREATE OR REPLACE FUNCTION mtmf.group_add(
    id_value uuid,
    tenant_id_value uuid,
    name_value text,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH inserted AS (
        INSERT INTO mtmf.group (id, tenant_id, name, deletion_status, extension)
        VALUES (id_value, tenant_id_value, name_value, deletion_status_value, extension_value)
        ON CONFLICT (id) DO NOTHING
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM inserted);
$$;

CREATE OR REPLACE FUNCTION mtmf.group_get(id_value uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'id', id,
        'tenant_id', tenant_id,
        'name', name,
        'deletion_status', deletion_status,
        'extension', extension
    )
    FROM mtmf.group
    WHERE id = id_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.group_save(
    id_value uuid,
    name_value text,
    deletion_status_value smallint,
    extension_value jsonb
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
    WITH updated AS (
        UPDATE mtmf.group
        SET name = name_value,
            deletion_status = deletion_status_value,
            extension = extension_value
        WHERE id = id_value
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM updated);
$$;
