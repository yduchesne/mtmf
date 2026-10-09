-- v004: Role aggregate repository functions.
--
-- A Role owns its ordered PermissionSets, which own their ordered
-- Permissions. ``role_add`` and ``role_save`` each write the complete
-- aggregate in one statement inside the caller's transaction; a failure
-- anywhere leaves no partially committed child. ``role_get`` rehydrates
-- the aggregate with stable positional ordering (ordering is structural
-- only and never encodes authorization precedence).
--
-- Python normally supplies a coherent payload built from validated domain
-- objects, but a malicious direct caller of this approved SECURITY DEFINER
-- function is within the threat model, so the function independently
-- re-checks child ownership. Two checks matter:
--
--   1. payload-internal ownership (``role_urn`` on each PermissionSet,
--      ``permission_set_id`` on each Permission); and
--   2. persisted-parent ownership for ``role_save``: any existing
--      PermissionSet UUID must still belong to the saved Role, and any
--      existing Permission UUID must still belong to its enclosing
--      payload PermissionSet. This prevents a delete-and-reinsert save
--      from reparenting a currently persisted child identity, which
--      payload-internal validation alone cannot detect.
--
-- Both are enforced by ``role_validate_children`` *before* any destructive
-- write; ``role_insert_children`` only performs the inserts. The checks
-- compare UUIDs as UUIDs and never interpolate payload values into SQL
-- identifiers or SQL text.

CREATE OR REPLACE FUNCTION mtmf.role_validate_children(
    role_urn_value text,
    payload_value jsonb,
    check_persisted boolean
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
        WHERE (permission->>'permission_set_id')::uuid
              IS DISTINCT FROM (item->>'id')::uuid
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'an owned Permission points at a different PermissionSet';
    END IF;

    IF check_persisted THEN
        -- For every incoming PermissionSet UUID that already exists, its
        -- stored parent association must be unchanged. A UUID currently
        -- owned by another Role can never be reassigned by saving this one.
        IF EXISTS (
            SELECT 1
            FROM jsonb_array_elements(permission_sets) AS incoming
            JOIN mtmf.permission_set AS existing
              ON existing.id = (incoming->>'id')::uuid
            WHERE existing.role_urn IS DISTINCT FROM role_urn_value
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT001',
                MESSAGE = 'an existing PermissionSet UUID belongs to a different persisted Role and cannot be reassigned';
        END IF;

        -- For every incoming Permission UUID that already exists, its
        -- stored PermissionSet association must be unchanged; moving a
        -- persisted Permission to another PermissionSet (even within the
        -- same Role) is reparenting and is rejected.
        IF EXISTS (
            SELECT 1
            FROM jsonb_array_elements(permission_sets) AS incoming_set
            CROSS JOIN LATERAL jsonb_array_elements(incoming_set->'permissions') AS incoming_permission
            JOIN mtmf.permission AS existing
              ON existing.id = (incoming_permission->>'id')::uuid
            WHERE existing.permission_set_id
                  IS DISTINCT FROM (incoming_set->>'id')::uuid
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT001',
                MESSAGE = 'an existing Permission UUID belongs to a different persisted PermissionSet and cannot be reassigned';
        END IF;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mtmf.role_insert_children(
    role_urn_value text,
    payload_value jsonb
)
RETURNS void
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    INSERT INTO mtmf.permission_set (id, role_urn, effect, position)
    SELECT (item->>'id')::uuid,
           role_urn_value,
           item->>'effect',
           (item_ordinality - 1)
    FROM jsonb_array_elements(payload_value->'permission_sets') WITH ORDINALITY
        AS sets(item, item_ordinality);

    INSERT INTO mtmf.permission (id, permission_set_id, urn, position)
    SELECT (permission->>'id')::uuid,
           (item->>'id')::uuid,
           permission->>'urn',
           (permission_ordinality - 1)
    FROM jsonb_array_elements(payload_value->'permission_sets') AS item
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

    -- A new Role has no persisted children, so only payload-internal
    -- ownership is validated; genuine UUID collisions with another Role
    -- still fail deterministically on the primary key.
    PERFORM mtmf.role_validate_children(role_urn_value, payload_value, false);
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

    -- Validate payload-internal ownership and persisted child parentage
    -- BEFORE any destructive write, so a rejected save cannot even
    -- transiently delete a child or change Role metadata. A plain
    -- snapshot read is sufficient for the currently-persisted-UUID
    -- guarantee: a concurrent delete/reinsert of the same UUID is
    -- observed either as the pre-delete committed parent or the
    -- post-reinsert committed parent, and a same-version change to the
    -- parent is impossible because ``role_save`` can only reinsert a
    -- child under the Role it is saving. Reuse of a UUID after its owning
    -- transaction has committed a removal is explicitly out of scope
    -- (there are no child tombstones).
    PERFORM mtmf.role_validate_children(role_urn_value, payload_value, true);

    UPDATE mtmf.role
    SET name = payload_value->>'name',
        description = coalesce(payload_value->>'description', ''),
        extension = coalesce(payload_value->'extension', '{}'::jsonb)
    WHERE urn = role_urn_value;

    -- Whole-aggregate replacement: retained child UUIDs keep their
    -- persisted parent associations (enforced above), removed children are
    -- deleted, and genuinely new children insert. A child is never
    -- reparented; immutable child columns are never updated.
    DELETE FROM mtmf.permission
    WHERE permission_set_id IN (
        SELECT id FROM mtmf.permission_set WHERE role_urn = role_urn_value
    );
    DELETE FROM mtmf.permission_set WHERE role_urn = role_urn_value;

    PERFORM mtmf.role_insert_children(role_urn_value, payload_value);
    RETURN true;
END;
$$;
