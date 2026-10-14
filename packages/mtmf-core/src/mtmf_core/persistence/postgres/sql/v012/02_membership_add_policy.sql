-- v012: exact membership-add Action and sole built-in Role grant (PR 19C).
--
-- Human-approved policy (Amendment 01 §A):
--   Action     urn:mtmf:iam:actions:system:identity-group-membership:add-object
--   Permission urn:mtmf:iam:permissions:system:identity-group-membership:add-object
--   Sole grant urn:mtmf:iam:roles:system:tenant-administrator (exact ALLOW only)
--
-- The seed is installation/operator-only, owner-owned, SECURITY INVOKER with
-- a fixed empty search_path, and is never granted to mtmf_runtime. It is
-- replay-safe: an exact pre-existing Action/Permission is accepted, while a
-- conflicting UUID/URN/position fails closed and rolls back; drift is never
-- silently repaired. The historical v006 assertion of the original three
-- Actions and eleven Permissions is left byte-for-byte intact.

CREATE OR REPLACE FUNCTION mtmf.install_membership_add_policy()
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    action_urn_value constant text :=
        'urn:mtmf:iam:actions:system:identity-group-membership:add-object';
    permission_urn_value constant text :=
        'urn:mtmf:iam:permissions:system:identity-group-membership:add-object';
    permission_id_value constant uuid := '5ad78530-2945-4f66-8ce1-ddbd8794d7b2';
    tenant_admin_urn constant text := 'urn:mtmf:iam:roles:system:tenant-administrator';
    set_id_value uuid;
    stored_set uuid;
    stored_urn text;
    stored_position integer;
BEGIN
    INSERT INTO mtmf.action (urn)
    VALUES (action_urn_value)
    ON CONFLICT (urn) DO NOTHING;

    SELECT ps.id INTO set_id_value
      FROM mtmf.permission_set AS ps
     WHERE ps.role_urn = tenant_admin_urn
     ORDER BY ps.position
     LIMIT 1;
    IF set_id_value IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT010',
            MESSAGE = 'membership-add policy seed requires the Tenant Administrator PermissionSet';
    END IF;

    INSERT INTO mtmf.permission (id, permission_set_id, urn, position)
    VALUES (permission_id_value, set_id_value, permission_urn_value, 1)
    ON CONFLICT (id) DO NOTHING;

    -- Exact replay or fail-closed conflict: never repair drift.
    SELECT p.permission_set_id, p.urn, p.position
      INTO stored_set, stored_urn, stored_position
      FROM mtmf.permission AS p
     WHERE p.id = permission_id_value;
    IF stored_set IS DISTINCT FROM set_id_value
       OR stored_urn IS DISTINCT FROM permission_urn_value
       OR stored_position IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT010',
            MESSAGE = 'membership-add Permission conflicts with the approved definition';
    END IF;
    IF EXISTS (
        SELECT 1 FROM mtmf.permission AS p
         WHERE p.permission_set_id = set_id_value
           AND p.position = 1
           AND p.id <> permission_id_value
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT010',
            MESSAGE = 'membership-add Permission position is occupied by a different definition';
    END IF;
END;
$$;

SELECT mtmf.install_membership_add_policy();
