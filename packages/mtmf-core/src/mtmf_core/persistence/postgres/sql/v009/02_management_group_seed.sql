-- v009: approved PR 11 management Roles.
--
-- Two SYSTEM-owned Role aggregates are installed, each owning exactly one
-- ALLOW PermissionSet containing exactly one exact Permission for the
-- Action ``tenant:get-object``. The Role URNs and the four UUID literals are
-- approved installation constants derived with the PR 10 deterministic
-- UUIDv5 namespace (``df87448f-4a54-5c73-bf35-c61c85406363``):
--
--   PermissionSet = uuid5(namespace, 'permission-set:' + role_urn)
--   Permission    = uuid5(namespace, 'permission:' + role_urn + ':' + permission_urn)
--
-- ``install_management_roles`` is owner-owned and deliberately SECURITY
-- INVOKER (owner/migrator installation context), pins ``search_path = ''``
-- and is never granted to ``mtmf_runtime``. An identical replay is a no-op;
-- any conflicting existing definition fails closed with ``MT010``.

CREATE OR REPLACE FUNCTION mtmf.install_management_roles()
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
    entry record;
    role_urn_value text;
    action_urn_value text;
    permission_urn_value text;
    stored_role_tenant uuid;
    stored_set_role text;
    stored_set_effect text;
    stored_permission_set uuid;
    stored_permission_urn text;
    set_count integer;
    permission_count integer;
BEGIN
    FOR entry IN
        SELECT *
        FROM (
            VALUES
                (
                    'root-tenant-management',
                    'ROOT Tenant Management',
                    '941a7c76-2720-5e1a-9230-c455daceb05f'::uuid,
                    'bf685dca-4912-5f31-8840-7ee604319b38'::uuid
                ),
                (
                    'tenant-management',
                    'Tenant Management',
                    '2f5e2e41-04ed-524c-96a8-bf79b1ad0f65'::uuid,
                    '196990b7-e325-5419-86e7-3ddeb67a7781'::uuid
                )
        ) AS seed(role_suffix, role_name, set_id, permission_id)
    LOOP
        role_urn_value := 'urn:mtmf:iam:roles:system:' || entry.role_suffix;
        action_urn_value := 'urn:mtmf:iam:actions:system:tenant:get-object';
        permission_urn_value := 'urn:mtmf:iam:permissions:system:tenant:get-object';

        INSERT INTO mtmf.action (urn)
        VALUES (action_urn_value)
        ON CONFLICT (urn) DO NOTHING;

        INSERT INTO mtmf.role (urn, name, description, defining_tenant_id, extension)
        VALUES (role_urn_value, entry.role_name, '', NULL, '{}'::jsonb)
        ON CONFLICT (urn) DO NOTHING;

        SELECT r.defining_tenant_id
          INTO stored_role_tenant
          FROM mtmf.role AS r
         WHERE r.urn = role_urn_value;
        IF stored_role_tenant IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT010',
                MESSAGE = 'management Role ' || role_urn_value
                          || ' is not a SYSTEM-owned definition';
        END IF;

        INSERT INTO mtmf.permission_set (id, role_urn, effect, position)
        VALUES (entry.set_id, role_urn_value, 'allow', 0)
        ON CONFLICT (id) DO NOTHING;

        SELECT count(*)
          INTO set_count
          FROM mtmf.permission_set AS ps
         WHERE ps.role_urn = role_urn_value;
        IF set_count <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT010',
                MESSAGE = 'management Role ' || role_urn_value
                          || ' must own exactly one approved PermissionSet, found '
                          || set_count::text;
        END IF;

        SELECT ps.role_urn, ps.effect
          INTO stored_set_role, stored_set_effect
          FROM mtmf.permission_set AS ps
         WHERE ps.id = entry.set_id;
        IF stored_set_role IS DISTINCT FROM role_urn_value
           OR stored_set_effect IS DISTINCT FROM 'allow' THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT010',
                MESSAGE = 'management PermissionSet ' || entry.set_id::text
                          || ' conflicts with the approved definition';
        END IF;

        INSERT INTO mtmf.permission (id, permission_set_id, urn, position)
        VALUES (entry.permission_id, entry.set_id, permission_urn_value, 0)
        ON CONFLICT (id) DO NOTHING;

        SELECT count(*)
          INTO permission_count
          FROM mtmf.permission AS p
         WHERE p.permission_set_id = entry.set_id;
        IF permission_count <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT010',
                MESSAGE = 'management PermissionSet ' || entry.set_id::text
                          || ' must own exactly one approved Permission, found '
                          || permission_count::text;
        END IF;

        SELECT p.permission_set_id, p.urn
          INTO stored_permission_set, stored_permission_urn
          FROM mtmf.permission AS p
         WHERE p.id = entry.permission_id;
        IF stored_permission_set IS DISTINCT FROM entry.set_id
           OR stored_permission_urn IS DISTINCT FROM permission_urn_value THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MT010',
                MESSAGE = 'management Permission ' || entry.permission_id::text
                          || ' conflicts with the approved definition';
        END IF;

        INSERT INTO mtmf.builtin_role (role_urn)
        VALUES (role_urn_value)
        ON CONFLICT (role_urn) DO NOTHING;
    END LOOP;
END;
$$;

SELECT mtmf.install_management_roles();
