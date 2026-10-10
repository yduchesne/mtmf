-- v006: approved Gate M minimum built-in IAM seed (PR #38).
--
-- Exactly eleven SYSTEM-owned Role aggregates, each owning one ALLOW
-- PermissionSet with one exact Permission, plus exactly three shared Action
-- definitions. The literal URNs and 22 UUIDs are copied from
-- ``docs/PR10_GATE_M_SEED_POLICY.md``; they are immutable installation
-- constants and MUST NOT be regenerated or normalized.
--
-- ``install_builtin_policy`` is owner-owned and deliberately SECURITY
-- INVOKER (it runs in the owner/migrator installation context, like the other
-- private helpers, so it never appears in the SECURITY DEFINER entry-point
-- inventory). It pins ``search_path = ''`` and is deliberately NOT granted to
-- ``mtmf_runtime``. It is invoked once by the migration in the owner
-- transaction. An identical
-- replay is a no-op; any pre-existing row whose semantic identity or approved
-- definition differs fails closed with a structural error and rolls back the
-- whole transaction -- it never silently overwrites or repairs policy.

CREATE OR REPLACE FUNCTION mtmf.install_builtin_policy()
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
                    'system-administrator',
                    'System Administrator',
                    'tenant:get-object',
                    'b04f0a3d-5d52-5c14-bb45-6ee07169eec0'::uuid,
                    'fa32a700-21d8-55fb-8e50-46f6d236d731'::uuid
                ),
                (
                    'system-security-administrator',
                    'System Security Administrator',
                    'role:get-object',
                    'b72dfbeb-59b4-5e36-bcd1-d707bc80571a'::uuid,
                    '747273b4-90b8-53da-b67b-029b3b336ac1'::uuid
                ),
                (
                    'system-reader',
                    'System Reader',
                    'tenant:get-object',
                    '1f9a65c9-cf69-516b-86f3-6cb459ae0b5e'::uuid,
                    '894a1b10-2e42-51d0-a21b-cd9b15676a69'::uuid
                ),
                (
                    'tenant-administrator',
                    'Tenant Administrator',
                    'tenant:get-object',
                    '187bc3cd-993d-5660-a226-113411121fed'::uuid,
                    'e7943319-187f-55b4-835a-059bf4ab7206'::uuid
                ),
                (
                    'tenant-security-administrator',
                    'Tenant Security Administrator',
                    'role:get-object',
                    '1526c205-21da-551f-8048-493467be2e19'::uuid,
                    'ac9ee2ad-87f0-5fe8-a273-fe3b70a3edc2'::uuid
                ),
                (
                    'tenant-contributor',
                    'Tenant Contributor',
                    'tenant:get-object',
                    'aded7e13-b6de-54fd-8ddd-de1009611179'::uuid,
                    '713c550d-b88c-5ec8-882e-7c592884bebd'::uuid
                ),
                (
                    'tenant-reader',
                    'Tenant Reader',
                    'tenant:get-object',
                    'babc80ad-448a-5533-81c0-a558b43f2434'::uuid,
                    '8260fdea-7bb7-5b4c-9433-44006e39fdf3'::uuid
                ),
                (
                    'organization-administrator',
                    'Organization Administrator',
                    'organization:get-object',
                    'ea4c7027-67f1-52f5-b249-3006c41b122b'::uuid,
                    '9e6153ad-0071-5a89-a322-a69185b9e32a'::uuid
                ),
                (
                    'organization-security-administrator',
                    'Organization Security Administrator',
                    'role:get-object',
                    '3d7d1473-bdba-53fa-a841-8ec02ce326db'::uuid,
                    '92ca8929-3563-5387-92a7-bf0679a10132'::uuid
                ),
                (
                    'organization-contributor',
                    'Organization Contributor',
                    'organization:get-object',
                    '2cab5378-81e9-53e6-966e-9aa7813e96d9'::uuid,
                    '40fcf83f-37d6-5a50-aa60-d371dc739aad'::uuid
                ),
                (
                    'organization-reader',
                    'Organization Reader',
                    'organization:get-object',
                    '2d937b29-264e-578a-83d1-21cd13c6923e'::uuid,
                    'd18a1bd3-dc89-5e64-a019-64a419dd3f75'::uuid
                )
        ) AS seed(role_suffix, role_name, permission_suffix, set_id, permission_id)
    LOOP
        role_urn_value := 'urn:mtmf:iam:roles:system:' || entry.role_suffix;
        action_urn_value := 'urn:mtmf:iam:actions:system:' || entry.permission_suffix;
        permission_urn_value := 'urn:mtmf:iam:permissions:system:' || entry.permission_suffix;

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
                MESSAGE = 'built-in Role ' || role_urn_value
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
                MESSAGE = 'built-in Role ' || role_urn_value
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
                MESSAGE = 'built-in PermissionSet ' || entry.set_id::text
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
                MESSAGE = 'built-in PermissionSet ' || entry.set_id::text
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
                MESSAGE = 'built-in Permission ' || entry.permission_id::text
                          || ' conflicts with the approved definition';
        END IF;

        INSERT INTO mtmf.builtin_role (role_urn)
        VALUES (role_urn_value)
        ON CONFLICT (role_urn) DO NOTHING;
    END LOOP;
END;
$$;

SELECT mtmf.install_builtin_policy();
