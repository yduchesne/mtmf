-- v012: post-migration assertions (defense in depth).
--
-- The mandatory post-upgrade runtime verifier (exact signature manifest)
-- remains authoritative. These assertions verify the cumulative policy state
-- and the closed legacy bypass inside the migration transaction.

DO $$
DECLARE
    action_count integer;
    membership_permission_count integer;
    tenant_admin_permissions integer;
    other_builtin_permissions integer;
    total_builtin_permissions integer;
    runtime_grant_count integer;
    new_entry_points integer;
    legacy_runtime boolean;
    public_can_execute integer;
    runtime_table_privileges integer;
BEGIN
    SELECT count(*)
      INTO action_count
      FROM mtmf.action
     WHERE urn = 'urn:mtmf:iam:actions:system:identity-group-membership:add-object';
    IF action_count <> 1 THEN
        RAISE EXCEPTION 'v012 assertion failed: the approved membership-add Action is missing';
    END IF;

    SELECT count(*)
      INTO membership_permission_count
      FROM mtmf.permission AS p
      JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id
     WHERE ps.role_urn = 'urn:mtmf:iam:roles:system:tenant-administrator'
       AND p.urn = 'urn:mtmf:iam:permissions:system:identity-group-membership:add-object';
    IF membership_permission_count <> 1 THEN
        RAISE EXCEPTION 'v012 assertion failed: the membership-add Permission is not granted exactly once';
    END IF;

    SELECT count(*)
      INTO tenant_admin_permissions
      FROM mtmf.permission AS p
      JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id
     WHERE ps.role_urn = 'urn:mtmf:iam:roles:system:tenant-administrator';
    IF tenant_admin_permissions <> 2 THEN
        RAISE EXCEPTION
            'v012 assertion failed: Tenant Administrator must own exactly two Permissions, found %',
            tenant_admin_permissions;
    END IF;

    SELECT count(*)
      INTO other_builtin_permissions
      FROM mtmf.permission AS p
      JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id
      JOIN mtmf.builtin_role AS br ON br.role_urn = ps.role_urn
     WHERE ps.role_urn <> 'urn:mtmf:iam:roles:system:tenant-administrator';
    IF other_builtin_permissions <> 12 THEN
        RAISE EXCEPTION
            'v012 assertion failed: the other twelve built-in Roles must retain one Permission each, found %',
            other_builtin_permissions;
    END IF;

    SELECT count(*)
      INTO total_builtin_permissions
      FROM mtmf.permission AS p
      JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id
      JOIN mtmf.builtin_role AS br ON br.role_urn = ps.role_urn;
    IF total_builtin_permissions <> 14 THEN
        RAISE EXCEPTION
            'v012 assertion failed: cumulative built-in Permissions must be exactly 14, found %',
            total_builtin_permissions;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM mtmf.permission AS p
        JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id
        JOIN mtmf.builtin_role AS br ON br.role_urn = ps.role_urn
        WHERE p.urn LIKE '%*%'
    ) THEN
        RAISE EXCEPTION 'v012 assertion failed: built-in Permissions must not contain wildcards';
    END IF;

    -- Exactly 78 approved runtime entry points: 77 through v011, minus the
    -- revoked legacy membership add, plus the two v012 entry points.
    SELECT count(*)
      INTO runtime_grant_count
      FROM pg_catalog.pg_proc AS p
      JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF runtime_grant_count <> 78 THEN
        RAISE EXCEPTION
            'v012 assertion failed: runtime EXECUTE allowlist must be exactly 78 functions, found %',
            runtime_grant_count;
    END IF;

    SELECT count(*)
      INTO new_entry_points
      FROM pg_catalog.pg_proc AS p
      JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf'
       AND p.proname IN (
           'identity_group_membership_add_lock',
           'identity_group_membership_add_verified'
       )
       AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE');
    IF new_entry_points <> 2 THEN
        RAISE EXCEPTION 'v012 assertion failed: the two membership-add entry points must be granted';
    END IF;

    SELECT has_function_privilege(
        'mtmf_runtime',
        'mtmf.identity_group_membership_add(uuid, uuid)',
        'EXECUTE'
    ) INTO legacy_runtime;
    IF legacy_runtime THEN
        RAISE EXCEPTION 'v012 assertion failed: the legacy membership-add function remains runtime-executable';
    END IF;

    SELECT count(*)
      INTO public_can_execute
      FROM pg_catalog.pg_proc AS p
      JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
     WHERE n.nspname = 'mtmf' AND has_function_privilege('public', p.oid, 'EXECUTE');
    IF public_can_execute <> 0 THEN
        RAISE EXCEPTION 'v012 assertion failed: PUBLIC must not EXECUTE MTMF functions';
    END IF;

    SELECT count(*)
      INTO runtime_table_privileges
      FROM information_schema.table_privileges
     WHERE table_schema = 'mtmf'
       AND grantee = 'mtmf_runtime'
       AND table_name = 'security_mutation_audit';
    IF runtime_table_privileges <> 0 THEN
        RAISE EXCEPTION 'v012 assertion failed: mtmf_runtime must not hold audit table privileges';
    END IF;
END;
$$;
