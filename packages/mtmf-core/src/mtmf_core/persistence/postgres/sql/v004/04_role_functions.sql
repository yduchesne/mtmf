-- v004: Role aggregate repository functions.
--
-- A Role owns its ordered PermissionSets, which own their ordered
-- Permissions. ``role_add`` and ``role_save`` each write the complete
-- aggregate in one statement inside the caller's transaction; a failure
-- anywhere leaves no partially committed child. ``role_get`` rehydrates
-- the aggregate with stable positional ordering (ordering is structural
-- only and never encodes authorization precedence).
--
-- Python always supplies a coherent payload built from validated domain
-- objects; the reviewed function re-checks child ownership independently
-- (``role_urn`` on each PermissionSet, ``permission_set_id`` on each
-- Permission) so a forged direct call cannot reparent a child.

CREATE OR REPLACE FUNCTION mtmf.role_insert_children(
    role_urn_value text,
    payload_value jsonb
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
DECLARE
    permission_sets jsonb := payload_value->'permission_sets';
BEGIN
    IF permission_sets IS NULL
       OR jsonb_typeof(permission_sets) <> 'array'
       OR jsonb_array_length(permission_sets) = 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT003',
            MESSAGE = 'a Role aggregate requires at least one PermissionSet';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(permission_sets) AS item
        WHERE item->>'role_urn' IS DISTINCT FROM role_urn_value
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'an owned PermissionSet points at a different Role';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(permission_sets) AS item
        WHERE item->'permissions' IS NULL
           OR jsonb_typeof(item->'permissions') <> 'array'
           OR jsonb_array_length(item->'permissions') = 0
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT003',
            MESSAGE = 'a PermissionSet requires at least one Permission';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(permission_sets) AS item
        CROSS JOIN LATERAL jsonb_array_elements(item->'permissions') AS permission
        WHERE permission->>'permission_set_id' IS DISTINCT FROM item->>'id'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'an owned Permission points at a different PermissionSet';
    END IF;

    INSERT INTO mtmf.permission_set (id, role_urn, effect, position)
    SELECT (item->>'id')::uuid,
           role_urn_value,
           item->>'effect',
           (item_ordinality - 1)
    FROM jsonb_array_elements(permission_sets) WITH ORDINALITY AS sets(item, item_ordinality);

    INSERT INTO mtmf.permission (id, permission_set_id, urn, position)
    SELECT (permission->>'id')::uuid,
           (item->>'id')::uuid,
           permission->>'urn',
           (permission_ordinality - 1)
    FROM jsonb_array_elements(permission_sets) AS item
    CROSS JOIN LATERAL jsonb_array_elements(item->'permissions') WITH ORDINALITY
        AS permissions(permission, permission_ordinality);
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.role_add(payload_value jsonb)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    role_urn_value text;
BEGIN
    IF payload_value IS NULL OR jsonb_typeof(payload_value) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT003',
            MESSAGE = 'a Role payload must be a JSON object';
    END IF;
    role_urn_value := payload_value->>'urn';
    IF role_urn_value IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT003',
            MESSAGE = 'a Role payload must carry its canonical URN';
    END IF;

    INSERT INTO mtmf.role (urn, name, description, defining_tenant_id, extension)
    VALUES (
        role_urn_value,
        payload_value->>'name',
        coalesce(payload_value->>'description', ''),
        nullif(payload_value->>'defining_tenant_id', '')::uuid,
        coalesce(payload_value->'extension', '{}'::jsonb)
    )
    ON CONFLICT (urn) DO NOTHING;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    PERFORM mtmf.role_insert_children(role_urn_value, payload_value);
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.role_get(urn_value text)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT jsonb_build_object(
        'urn', r.urn,
        'name', r.name,
        'description', r.description,
        'defining_tenant_id', r.defining_tenant_id,
        'extension', r.extension,
        'permission_sets', coalesce(
            (
                SELECT jsonb_agg(
                    jsonb_build_object(
                        'id', ps.id,
                        'role_urn', ps.role_urn,
                        'effect', ps.effect,
                        'permissions', coalesce(
                            (
                                SELECT jsonb_agg(
                                    jsonb_build_object(
                                        'id', p.id,
                                        'permission_set_id', p.permission_set_id,
                                        'urn', p.urn
                                    )
                                    ORDER BY p.position
                                )
                                FROM mtmf.permission p
                                WHERE p.permission_set_id = ps.id
                            ),
                            '[]'::jsonb
                        )
                    )
                    ORDER BY ps.position
                )
                FROM mtmf.permission_set ps
                WHERE ps.role_urn = r.urn
            ),
            '[]'::jsonb
        )
    )
    FROM mtmf.role r
    WHERE r.urn = urn_value;
$$;

CREATE OR REPLACE FUNCTION mtmf.role_save(payload_value jsonb)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    role_urn_value text;
    existing_tenant uuid;
BEGIN
    IF payload_value IS NULL OR jsonb_typeof(payload_value) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT003',
            MESSAGE = 'a Role payload must be a JSON object';
    END IF;
    role_urn_value := payload_value->>'urn';
    IF role_urn_value IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT003',
            MESSAGE = 'a Role payload must carry its canonical URN';
    END IF;

    SELECT defining_tenant_id INTO existing_tenant
    FROM mtmf.role
    WHERE urn = role_urn_value
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- The Role URN and structural definition Tenant are immutable; a save
    -- can never silently reparent a Role into another namespace.
    IF existing_tenant IS DISTINCT FROM nullif(payload_value->>'defining_tenant_id', '')::uuid THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'Role definition ownership is immutable and cannot be changed';
    END IF;

    UPDATE mtmf.role
    SET name = payload_value->>'name',
        description = coalesce(payload_value->>'description', ''),
        extension = coalesce(payload_value->'extension', '{}'::jsonb)
    WHERE urn = role_urn_value;

    -- Whole-aggregate replacement: retained child UUIDs are preserved by
    -- the payload, removed children are deleted, and new children insert.
    -- No child is reparented (immutable child columns are never updated).
    DELETE FROM mtmf.permission
    WHERE permission_set_id IN (
        SELECT id FROM mtmf.permission_set WHERE role_urn = role_urn_value
    );
    DELETE FROM mtmf.permission_set WHERE role_urn = role_urn_value;

    PERFORM mtmf.role_insert_children(role_urn_value, payload_value);
    RETURN true;
END;
$$;
