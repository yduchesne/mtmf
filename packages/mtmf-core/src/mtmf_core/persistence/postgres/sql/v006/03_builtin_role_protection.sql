-- v006: database-enforced protection for the approved built-in SYSTEM policy.
--
-- ``role_save`` is the only runtime-granted path that can rewrite a Role
-- aggregate (it deletes and reinserts child PermissionSets/Permissions).
-- This replacement rejects any save whose target Role URN is registered in
-- ``mtmf.builtin_role``, so an ordinary runtime caller cannot alter the
-- approved built-in definitions. Controlled owner/migrator migrations evolve
-- the policy with direct SQL and do not use this entry point.
--
-- ``role_add`` already uses ``ON CONFLICT (urn) DO NOTHING`` and returns
-- false without mutating an existing Role, so it cannot replace a built-in
-- definition; it is deliberately left unchanged.

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

    -- PR 10: the reviewed built-in SYSTEM Role definitions are protected.
    IF EXISTS (
        SELECT 1
        FROM mtmf.builtin_role AS br
        WHERE br.role_urn = role_urn_value
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT010',
            MESSAGE = 'built-in SYSTEM Role definitions are protected and cannot '
                      'be modified by role_save';
    END IF;

    SELECT defining_tenant_id INTO existing_tenant
    FROM mtmf.role
    WHERE urn = role_urn_value
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    IF existing_tenant IS DISTINCT FROM nullif(payload_value->>'defining_tenant_id', '')::uuid THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'Role definition ownership is immutable and cannot be changed';
    END IF;

    PERFORM mtmf.role_validate_children(role_urn_value, payload_value, true);

    UPDATE mtmf.role
    SET name = payload_value->>'name',
        description = coalesce(payload_value->>'description', ''),
        extension = coalesce(payload_value->'extension', '{}'::jsonb)
    WHERE urn = role_urn_value;

    DELETE FROM mtmf.permission
    WHERE permission_set_id IN (
        SELECT id FROM mtmf.permission_set WHERE role_urn = role_urn_value
    );
    DELETE FROM mtmf.permission_set WHERE role_urn = role_urn_value;

    PERFORM mtmf.role_insert_children(role_urn_value, payload_value);
    RETURN true;
END;
$$;

-- The replacement preserves the reviewed owner/SECURITY DEFINER/no-search-
-- path posture and the exact runtime grant for the unchanged signature.
ALTER FUNCTION mtmf.role_save(payload_value jsonb) OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.role_save(payload_value jsonb) SECURITY DEFINER;
ALTER FUNCTION mtmf.role_save(payload_value jsonb) SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.role_save(payload_value jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mtmf.role_save(payload_value jsonb) TO mtmf_runtime;

-- The seed installer is installation-only, SECURITY INVOKER (owner/migrator
-- context), and is never runtime-executable.
ALTER FUNCTION mtmf.install_builtin_policy() OWNER TO mtmf_owner;
ALTER FUNCTION mtmf.install_builtin_policy() SECURITY INVOKER;
ALTER FUNCTION mtmf.install_builtin_policy() SET search_path = '';
REVOKE ALL ON FUNCTION mtmf.install_builtin_policy() FROM PUBLIC;
