-- v006: post-migration assertions (defense in depth).
--
-- These checks run inside the migration transaction and fail it (rolling
-- back the seed, the protection replacement, and all grants) if the approved
-- Gate M posture was not achieved. The mandatory post-upgrade runtime
-- verifier (exact signature manifest) remains authoritative.

DO $$
DECLARE
    builtin_count integer;
    action_count integer;
    builtin_permission_sets integer;
    builtin_permissions integer;
    public_can_execute boolean;
BEGIN
    SELECT count(*) INTO builtin_count FROM mtmf.builtin_role;
    IF builtin_count <> 11 THEN
        RAISE EXCEPTION
            'Gate M assertion failed: exactly 11 built-in SYSTEM Roles must be '
            'registered, found %',
            builtin_count;
    END IF;

    SELECT count(*)
      INTO action_count
      FROM mtmf.action
     WHERE urn IN (
         'urn:mtmf:iam:actions:system:tenant:get-object',
         'urn:mtmf:iam:actions:system:role:get-object',
         'urn:mtmf:iam:actions:system:organization:get-object'
     );
    IF action_count <> 3 THEN
        RAISE EXCEPTION
            'Gate M assertion failed: exactly 3 approved Action definitions must '
            'exist, found %',
            action_count;
    END IF;

    SELECT count(*)
      INTO builtin_permission_sets
      FROM mtmf.permission_set AS ps
      JOIN mtmf.builtin_role AS br ON br.role_urn = ps.role_urn;
    IF builtin_permission_sets <> 11 THEN
        RAISE EXCEPTION
            'Gate M assertion failed: each of the 11 built-in Roles must own '
            'exactly one PermissionSet (found % total)',
            builtin_permission_sets;
    END IF;

    SELECT count(*)
      INTO builtin_permissions
      FROM mtmf.permission AS p
      JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id
      JOIN mtmf.builtin_role AS br ON br.role_urn = ps.role_urn;
    IF builtin_permissions <> 11 THEN
        RAISE EXCEPTION
            'Gate M assertion failed: each of the 11 built-in PermissionSets must '
            'own exactly one Permission (found % total)',
            builtin_permissions;
    END IF;

    -- No built-in matcher may contain a wildcard.
    IF EXISTS (
        SELECT 1
        FROM mtmf.permission AS p
        JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id
        JOIN mtmf.builtin_role AS br ON br.role_urn = ps.role_urn
        WHERE p.urn LIKE '%*%'
    ) THEN
        RAISE EXCEPTION
            'Gate M assertion failed: built-in Permissions must not contain wildcards';
    END IF;

    -- The installation-only seed function must not be runtime-executable.
    IF has_function_privilege('mtmf_runtime', 'mtmf.install_builtin_policy()', 'EXECUTE') THEN
        RAISE EXCEPTION
            'Gate M assertion failed: mtmf_runtime must not EXECUTE install_builtin_policy';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL aclexplode(
            coalesce(p.proacl, acldefault('f', p.proowner))
        ) AS a
        WHERE n.nspname = 'mtmf'
          AND p.proname = 'install_builtin_policy'
          AND a.grantee = 0
          AND a.privilege_type = 'EXECUTE'
    ) INTO public_can_execute;
    IF public_can_execute THEN
        RAISE EXCEPTION
            'Gate M assertion failed: PUBLIC must not EXECUTE install_builtin_policy';
    END IF;
END;
$$;
